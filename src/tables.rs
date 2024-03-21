use std::fs;
use std::{fs::read_to_string, path::PathBuf, str::FromStr};
use tfhe::integer::wopbs::{IntegerWopbsLUT, WopbsKey};
use tfhe::integer::{
    BooleanBlock, ClientKey, IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext, ServerKey,
};
use tfhe::shortint::Ciphertext;

use crate::{EncryptedAtom, EncryptedSyntaxTree};

/// An enum with one variant for each possible type of a cell's content.
#[derive(Debug, Clone)]
pub enum CellType {
    Bool,
    U8,
    U16,
    U32,
    I8,
    I16,
    I32,
    ShortString,
}

impl CellType {
    /// given a type, returns its length when written as a vector of u32
    pub fn len(&self) -> usize {
        match self {
            Self::ShortString => 8,
            _ => 1,
        }
    }
}

/// Transforms a `&str` to a `CellType`. Typically used when reading table headers.
impl From<&str> for CellType {
    fn from(str_type: &str) -> Self {
        match str_type {
            "bool" => Self::Bool,
            "uint8" => Self::U8,
            "uint16" => Self::U16,
            "uint32" => Self::U32,
            "int8" => Self::I8,
            "int16" => Self::I16,
            "int32" => Self::I32,
            "string" => Self::ShortString,
            _ => panic!("Unknown data type: {str_type}"),
        }
    }
}

/// Holds the content of a given cell.
#[derive(Clone, Debug)]
pub enum CellContent {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    I8(i8),
    I16(i16),
    I32(i32),
    ShortString(String),
}

/// Returns the type of a given cell content.
impl From<&CellContent> for CellType {
    fn from(content: &CellContent) -> Self {
        match content {
            CellContent::Bool(_) => Self::Bool,
            CellContent::U8(_) => Self::U8,
            CellContent::U16(_) => Self::U16,
            CellContent::U32(_) => Self::U32,
            CellContent::I8(_) => Self::I8,
            CellContent::I16(_) => Self::I16,
            CellContent::I32(_) => Self::I32,
            CellContent::ShortString(_) => Self::ShortString,
        }
    }
}

impl CellContent {
    /// Returns a `String` representation of its content.
    pub fn to_string(&self) -> String {
        match self {
            Self::Bool(b) => format!("{b}"),
            Self::U8(u) => format!("{u}"),
            Self::U16(u) => format!("{u}"),
            Self::U32(u) => format!("{u}"),
            Self::I8(i) => format!("{i}"),
            Self::I16(i) => format!("{i}"),
            Self::I32(i) => format!("{i}"),
            Self::ShortString(s) => s.clone(),
        }
    }
    /// Encode every cell content as a vector of `u32`s. In every cases other than
    /// `ShortString`, it has a length of 1.
    pub fn encode(&self) -> Vec<u32> {
        // switch the MSB of signed integers so that
        // switch_sign8(-1) < switch_sign8(1)
        let switch_sign8 = |i: i8| (i as u32) ^ (1 << 31);
        let switch_sign16 = |i: i16| (i as u32) ^ (1 << 31);
        let switch_sign32 = |i: i32| (i as u32) ^ (1 << 31);
        match self {
            Self::Bool(b) => vec![*b as u32],
            Self::U8(u) => vec![*u as u32],
            Self::U16(u) => vec![*u as u32],
            Self::U32(u) => vec![*u as u32],
            Self::I8(i) => vec![switch_sign8(*i)],
            Self::I16(i) => vec![switch_sign16(*i)],
            Self::I32(i) => vec![switch_sign32(*i)],
            Self::ShortString(s) => {
                let s_len = s.len();
                let s_bytes = s.as_bytes();
                let mut result: Vec<u32> = Vec::new();
                let get_or_zero = |j: usize| (if j < s_len { s_bytes[j] } else { 0u8 }) as u32;
                for i in 0..8 {
                    let j = 4 * i;
                    let (b0, b1, b2, b3) = (
                        get_or_zero(j),
                        get_or_zero(j + 1),
                        get_or_zero(j + 2),
                        get_or_zero(j + 3),
                    );
                    let u32_from_bytes = (b0 << 24) + (b1 << 16) + (b2 << 8) + b3;
                    result.push(u32_from_bytes);
                }
                result
            }
        }
    }
    /// Encrypts everything as a FheUint32, except `ShortString` which is stored as a vector
    /// of eight `FheUint32`s.
    pub fn encrypt(&self, client_key: &ClientKey) -> Vec<RadixCiphertext> {
        self.encode()
            .iter()
            .map(|u| client_key.encrypt_radix(u.clone(), 16))
            .collect::<Vec<_>>()
    }
}

/// Parses a `&str` into a `CellContent` of type `CellType`.
impl From<(&str, &CellType)> for CellContent {
    fn from(arg: (&str, &CellType)) -> Self {
        match arg.1 {
            CellType::Bool => Self::Bool(bool::from_str(arg.0).unwrap()),
            CellType::U8 => Self::U8(u8::from_str(arg.0).unwrap()),
            CellType::U16 => Self::U16(u16::from_str(arg.0).unwrap()),
            CellType::U32 => Self::U32(u32::from_str(arg.0).unwrap()),
            CellType::I8 => Self::I8(i8::from_str(arg.0).unwrap()),
            CellType::I16 => Self::I16(i16::from_str(arg.0).unwrap()),
            CellType::I32 => Self::I32(i32::from_str(arg.0).unwrap()),
            CellType::ShortString => Self::ShortString(String::from(arg.0)),
        }
    }
}

/// A struct holding a vector of tuples `(column_identifier, data_type)`.
#[derive(Clone, Debug)]
pub struct TableHeaders(pub Vec<(String, CellType)>);

impl TableHeaders {
    /// Given a column identifier, returns the index of its first element. Each element is of type
    /// u32, so an column of type u32 has 1 associated index, a column of type ShortString has 8, etc.
    pub fn index_of(&self, column: String) -> Result<u8, String> {
        let mut result: u8 = 0;
        for (label, cell_type) in self.0.iter() {
            if label == &column {
                return Ok(result);
            }
            result += cell_type.len() as u8;
        }
        Err(format!("column '{column}' does not exist"))
    }
    // fn type_of(&self, column: String) -> Result<CellType, String> {
    //     for (label, cell_type) in self.0.iter() {
    //         if label == &column {
    //             return Ok(cell_type.clone());
    //         }
    //     }
    //     Err(format!("column '{column}' does not exist"))
    // }
}

/// A representation of a SQL table.
#[derive(Clone, Debug)]
pub struct Table {
    pub headers: TableHeaders,
    pub content: Vec<Vec<CellContent>>,
}

/// An encoded representation of a SQL table.
///
/// Each entry is stored as a `Vec<u32>`. A table is a vector of entries.
#[derive(Debug)]
pub struct EncodedTable {
    pub headers: TableHeaders,
    pub content: Vec<Vec<u32>>,
}

impl From<Table> for EncodedTable {
    fn from(table: Table) -> Self {
        Self {
            headers: table.headers.clone(),
            content: table
                .content
                .iter()
                .map(|entry| entry.iter().map(|cell| cell.encode()).flatten().collect())
                .collect::<Vec<Vec<u32>>>(),
        }
    }
}

impl EncodedTable {
    fn run_query_on_entry(
        &self,
        entry: &Vec<u32>,
        query: &EncryptedSyntaxTree,
        server_key: &ServerKey,
        wopbs_key: &WopbsKey,
    ) -> Ciphertext {
        if query.is_empty() {
            return server_key
                .create_trivial_radix::<u64, RadixCiphertext>(1u64, 1)
                .into_blocks()[0]
                .clone();
        }
        let entry_length = entry.len();
        // the server_key.generate_lut_radix() method needs a ciphertext for
        // computing the lut size. We use num_blocks = 4, i.e. we assume the
        // total number of columns in a table is lower than 4^4 = 256.
        let ct_entry_length: RadixCiphertext =
            server_key.create_trivial_radix(entry_length as u64, 4);
        let f = |u: u64| -> u64 {
            let v = u as usize;
            if v < entry_length {
                entry[v] as u64
            } else {
                0
            }
        };
        let lut = wopbs_key.generate_lut_radix(&ct_entry_length, f);

        // convenience closure for looking up an entry's cell content from an encrypted index
        let column_id_lut = |encrypted_id: &RadixCiphertext| -> RadixCiphertext {
            let ct = wopbs_key.keyswitch_to_wopbs_params(&server_key, encrypted_id);
            let ct_res = wopbs_key.wopbs(&ct, &lut);
            wopbs_key.keyswitch_to_pbs_params(&ct_res)
        };
        // convenience closure for negating a bool
        let negate_bool =
            |b: &RadixCiphertext| -> RadixCiphertext { server_key.unchecked_scalar_add(&b, 1) };
        // convenience closure for adding bools
        let add_bool = |b1: &RadixCiphertext, b2: &RadixCiphertext| -> RadixCiphertext {
            server_key.unchecked_add_parallelized(&b1, &b2)
        };
        // convenience closure for multiplying bools
        let mul_bool = |b1: &RadixCiphertext, b2: &RadixCiphertext| -> RadixCiphertext {
            server_key.unchecked_mul_parallelized(&b1, &b2)
        };
        let boolean_to_radix =
            |b: BooleanBlock| -> RadixCiphertext { b.into_radix(1, &server_key) };
        let ct_to_radix =
            |ct: Ciphertext| -> RadixCiphertext { RadixCiphertext::from_blocks(vec![ct]) };

        // run an encrypted atomic query
        let compute_atom = |encrypted_atom: &EncryptedAtom| {
            let (index, val, is_leq, negate) = encrypted_atom;
            let current_val = column_id_lut(&index);
            // is_leq * (current_val < val) + (current_val == val) + negate
            add_bool(
                &add_bool(
                    &mul_bool(
                        &ct_to_radix(is_leq.clone()),
                        &boolean_to_radix(server_key.lt_parallelized(&current_val, val)),
                    ),
                    &boolean_to_radix(server_key.eq_parallelized(&current_val, val)),
                ),
                &ct_to_radix(negate.clone()),
            )
        };

        let mut result_bool = server_key.create_trivial_radix(0u64, 1);
        let mut current_and_clause = compute_atom(&query[0].1);
        for (op, encrypted_atom) in query {
            let op_radix = ct_to_radix(op.clone());
            let atom_bool = compute_atom(encrypted_atom);
            // result_bool:
            //   | if !op: result_bool OR current_and_clause
            //   | else: result_bool
            // so we get:
            // result_bool = (op AND result_bool) XOR (!op AND (result_bool OR current_and_clause))
            // We then replace:
            // - a XOR b by a+b,
            // - a AND b by a*b,
            // - a OR b by a+b+a*b,
            // - !a by 1+a,
            // and compute modulo 2:
            // result_bool = op * result_bool + (1 + op) * (result_bool + current_and_clause
            //                                              + result_bool * current_and_clause)
            //             = result_bool + (1 + op) * current_and_clause * (1 + result_bool)

            // we need to create a temporary value so that rust's borrow checker doesn't throw an error
            let temp_bool = mul_bool(
                &negate_bool(&op_radix),
                &mul_bool(&current_and_clause, &negate_bool(&result_bool)),
            );
            server_key.add_assign_parallelized(&mut result_bool, &temp_bool);
            // current_and_clause:
            //   | if op: (current_and_clause AND atom_bool)
            //   | else: atom_bool
            // so we get:
            // current_and_clause = (op AND (current_and_clause AND atom_bool)) XOR (!op AND atom_bool)
            // and compute modulo 2:
            // current_and_clause = (op * current_and_clause * atom_bool) + (1 + op) * atom_bool
            //                    = atom_bool * (1 + op * (1 + current_and_clause))
            current_and_clause = mul_bool(
                &atom_bool,
                &negate_bool(&mul_bool(&op_radix, &negate_bool(&current_and_clause))),
            );
        }
        server_key
            .scalar_rem_parallelized(&result_bool, 2u8)
            .into_blocks()[0]
            .clone()
    }
    pub fn run_fhe_query(
        &self,
        query: &EncryptedSyntaxTree,
        server_key: &ServerKey,
        wopbs_key: &WopbsKey,
    ) -> Vec<Ciphertext> {
        // iterate through each entry
        self.content
            .iter()
            .map(|entry| self.run_query_on_entry(entry, query, server_key, wopbs_key))
            .collect()
    }
}

/// Updates a lookup table at the given index.
///
/// The argument `ct` is used internally to encode/decode indices. It should be the same
/// as the one used for `generate_lut_radix`. This function is mostly a copy-paste of the
/// method `WopbsKey::generate_lut_radix()`.
fn update_lut(
    index: usize,
    value: u32,
    lut: &mut IntegerWopbsLUT,
    ct: &RadixCiphertext,
    wopbs_key: &WopbsKey,
) {
    use tfhe::integer::wopbs::{decode_radix, encode_mix_radix, encode_radix};
    let value = value as u64;

    let basis = ct.moduli()[0];
    let block_nb = ct.blocks().len();
    let wopbs_inner = wopbs_key.clone().into_raw_parts();
    let (wopbs_message_modulus, wopbs_carry_modulus) = (
        wopbs_inner.param.message_modulus.0,
        wopbs_inner.param.carry_modulus.0,
    );
    let delta: u64 = (1 << 63) / (wopbs_message_modulus * wopbs_carry_modulus) as u64;
    let mut vec_deg_basis = vec![];

    let mut modulus = 1;
    for (i, deg) in ct.moduli().iter().zip(ct.blocks().iter()) {
        modulus *= i;
        let b = f64::log2((deg.degree.get() + 1) as f64).ceil() as u64;
        vec_deg_basis.push(b);
    }

    let encoded_with_deg_val = encode_mix_radix(index as u64, &vec_deg_basis, basis);
    let decoded_val = decode_radix(&encoded_with_deg_val, basis);
    let f_val = value % modulus;
    let encoded_f_val = encode_radix(f_val, basis, block_nb as u64);
    for (lut_number, radix_encoded_val) in encoded_f_val.iter().enumerate().take(block_nb) {
        lut[lut_number][index] = radix_encoded_val * delta;
    }
}

/// A vector of tuples `(table_name, table)`.
pub struct Tables {
    pub server_key: ServerKey,
    pub wopbs_key: WopbsKey,
    pub tables: Vec<(String, Table)>,
}

/// Parse headers of a csv file.
fn read_headers(path: PathBuf) -> TableHeaders {
    let header = read_to_string(path)
        .unwrap()
        .lines()
        .map(String::from)
        .nth(0)
        .unwrap()
        .clone();
    let mut result: Vec<(String, CellType)> = Vec::new();
    let mut header_split = header.split(',');
    while let Some(column) = header_split.next() {
        if let (Some(label), Some(cell_type)) = {
            let mut split = column.split(':');
            (split.next(), split.next().map(CellType::from))
        } {
            result.push((label.to_string(), cell_type));
        }
    }
    TableHeaders(result)
}

/// Loads a directory with structure:
/// - `db_dir`:
///   - `table_1.csv`
///   - `table_2.csv`
///   - ...
pub fn load_tables(
    path: PathBuf,
    server_key: ServerKey,
    wopbs_key: WopbsKey,
) -> Result<Tables, Box<dyn std::error::Error>> {
    let mut result: Vec<(String, Table)> = Vec::new();
    let db_path = fs::read_dir(path).expect("Database path error: can't read directory {path}");
    for table_file in db_path {
        let table_path = table_file?.path();
        let table_name: String = table_path
            .file_stem()
            .and_then(|f| f.to_str().map(|os_str| String::from(os_str)))
            .expect("file name error {table_path}");
        let headers = read_headers(table_path.clone());
        let mut rdr = csv::Reader::from_path(table_path)?;
        let mut content: Vec<Vec<CellContent>> = Vec::new();
        for entry in rdr.records() {
            let mut entry_content: Vec<CellContent> = Vec::with_capacity(headers.0.len());
            let inner_entry = entry.unwrap();
            let cell_iter = inner_entry.iter().zip(headers.0.clone());
            for (content, (_label, cell_type)) in cell_iter {
                entry_content.push(CellContent::from((content, &cell_type)));
            }
            content.push(entry_content);
        }
        result.push((table_name, Table { headers, content }))
    }
    Ok(Tables {
        server_key,
        wopbs_key,
        tables: result,
    })
}

mod tests {
    use super::*;
    use tfhe::{
        integer::{gen_keys_radix, RadixClientKey},
        shortint::{
            parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        },
    };

    fn generate_keys() -> (RadixClientKey, ServerKey, WopbsKey) {
        let (ck, sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 16);
        let wopbs_key = WopbsKey::new_wopbs_key(&ck, &sk, &WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        (ck, sk, wopbs_key)
    }

    #[test]
    fn update_lookup_table() {
        let (ck, sk, wopbs_key) = generate_keys();
        let ct_entry_length: RadixCiphertext = sk.create_trivial_radix(8u64, 4);
        let f = |u: u64| -> u64 { u + 5 };
        let mut lut = wopbs_key.generate_lut_radix(&ct_entry_length, f);
        update_lut(1, 3, &mut lut, &ct_entry_length, &wopbs_key);
        let apply_lut = |encrypted_id: &RadixCiphertext| -> RadixCiphertext {
            let ct = wopbs_key.keyswitch_to_wopbs_params(&sk, encrypted_id);
            let ct_res = wopbs_key.wopbs(&ct, &lut);
            wopbs_key.keyswitch_to_pbs_params(&ct_res)
        };
        // let lut_at_0 = apply_lut(&ck.as_ref().encrypt_radix(0u64, 4));
        let lut_at_1 = apply_lut(&sk.create_trivial_radix(1u64, 4));
        let lut_at_2 = apply_lut(&sk.create_trivial_radix(2u64, 4));
        let clear1: u32 = ck.decrypt(&lut_at_1);
        let clear2: u32 = ck.decrypt(&lut_at_2);
        assert_eq!(clear1, 3);
        assert_eq!(clear2, 7);
    }
}
