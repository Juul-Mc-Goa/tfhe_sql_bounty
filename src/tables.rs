use std::fs;
use std::{fs::read_to_string, path::PathBuf, str::FromStr};
use tfhe::integer::wopbs::WopbsKey;
use tfhe::integer::{ClientKey, RadixCiphertext, ServerKey};
use tfhe::shortint::{Ciphertext, WopbsParameters};

use crate::cipher_structs::{FheBool, UpdatableLUT};
use crate::EncryptedSyntaxTree;

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
// #[derive(Debug)]
pub struct TableQueryRunner<'a> {
    pub headers: TableHeaders,
    pub content: Vec<Vec<u32>>,
    pub server_key: &'a ServerKey,
    pub wopbs_key: &'a WopbsKey,
    pub wopbs_parameters: WopbsParameters,
}

impl<'a> TableQueryRunner<'a> {
    pub fn new(
        table: Table,
        server_key: &'a ServerKey,
        wopbs_key: &'a WopbsKey,
        wopbs_parameters: WopbsParameters,
    ) -> Self {
        Self {
            headers: table.headers.clone(),
            content: table
                .content
                .iter()
                .map(|entry| entry.iter().map(|cell| cell.encode()).flatten().collect())
                .collect::<Vec<Vec<u32>>>(),
            server_key,
            wopbs_key,
            wopbs_parameters,
        }
    }

    /// Runs an encrypted query on a given entry.
    ///
    /// Returns a Ciphertext encrypting a boolean that answers the question: "Is this entry
    /// selected by the query?"
    ///
    /// The encrypted boolean is actually an integer modulo 2, so that:
    /// - `a AND b` becomes `a*b`,
    /// - `a XOR b` becomes `a+b`,
    /// - `a OR b` becomes `a+b+a*b`,
    /// - `NOT a` becomes `1+a`.
    /// Then the boolean formulas are simplified so as to minimize the number of
    /// multiplications, using the fact that addition is much faster than PBS.
    fn run_query_on_entry(&self, entry: &Vec<u32>, query: &EncryptedSyntaxTree) -> Ciphertext {
        let sk = self.server_key;
        let lut = UpdatableLUT::new(entry, sk, self.wopbs_key, self.wopbs_parameters.clone());

        let new_fhe_bool = |ct: Ciphertext| FheBool { ct, server_key: sk };
        let mut result_bool = new_fhe_bool(sk.create_trivial_boolean_block(true).into_inner());

        let is_lt = |a: &RadixCiphertext, b: &RadixCiphertext| -> FheBool {
            new_fhe_bool(sk.lt_parallelized(a, b).into_inner())
        };

        let is_eq = |a: &RadixCiphertext, b: &RadixCiphertext| -> FheBool {
            new_fhe_bool(sk.eq_parallelized(a, b).into_inner())
        };

        if query.is_empty() {
            // if the condition is empty then return true
            return result_bool.ct;
        } else if query.len() == 1 {
            // if the condition is just one atom then return the atom boolean
            let (_, (index, val, is_leq, negate)) = &query[0];

            let op_is_leq: FheBool = new_fhe_bool(is_leq.clone());
            let current_value = lut.apply(index);

            // atom_bool = is_leq * (current_val < val) + (current_val == val) + negate
            let result = (op_is_leq * is_lt(&current_value, &val))
                + is_eq(&current_value, &val)
                + new_fhe_bool(negate.clone());

            return result.ct;
        }

        // else, loop through all atoms

        // initialize current_and_clause to be the first (boolean valued) op
        let mut current_and_clause = new_fhe_bool(query[0].0.clone());

        for (op, encrypted_atom) in query.iter() {
            let (index, val, is_leq, negate) = encrypted_atom;

            let current_value = lut.apply(index);
            let op_is_leq: FheBool = new_fhe_bool(is_leq.clone());

            // atom_bool = is_leq * (current_val < val) + (current_val == val) + negate
            let atom_bool = op_is_leq * is_lt(&current_value, &val)
                + is_eq(&current_value, &val)
                + new_fhe_bool(negate.clone());

            // result_bool:
            //   | if !op: result_bool OR current_and_clause
            //   | else: result_bool
            // so we get:
            // result_bool = (op AND result_bool) XOR (!op AND (result_bool OR current_and_clause))
            // and compute modulo 2:
            // result_bool = op * result_bool + (1 + op) * (result_bool + current_and_clause
            //                                              + result_bool * current_and_clause)
            //             = result_bool + (1 + op) * current_and_clause * (1 + result_bool)

            // (create a temporary value so that the borrow checker doesn't throw an error)
            let op_fhe_bool = new_fhe_bool(op.clone());
            let temp_bool = &!&op_fhe_bool * &current_and_clause * !&result_bool;
            result_bool += &temp_bool;

            // current_and_clause:
            //   | if op: (current_and_clause AND atom_bool)
            //   | else: atom_bool
            // so we get:
            // current_and_clause = (op AND (current_and_clause AND atom_bool)) XOR (!op AND atom_bool)
            // and compute modulo 2:
            // current_and_clause = (op * current_and_clause * atom_bool) + (1 + op) * atom_bool
            //                    = atom_bool * (1 + op * (1 + current_and_clause))
            current_and_clause = atom_bool * !(op_fhe_bool * !current_and_clause);
        }
        result_bool.ct
    }

    pub fn run_fhe_query(&self, query: &EncryptedSyntaxTree) -> Vec<Ciphertext> {
        // iterate through each entry
        self.content
            .iter()
            .map(|entry| self.run_query_on_entry(entry, query))
            .collect()
    }
}

/// A vector of tuples `(table_name, table)`, plus a `ServerKey` and a `WopbsKey`.
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
    use crate::generate_keys;

    // #[test]
    // fn update_lookup_table() {
    //     let (ck, sk, wopbs_key, wopbs_params) = generate_keys();
    //     let entry: Vec<u32> = vec![2, 3, 4, 5, 6];
    //     let mut lut = UpdatableLUT::new(&entry, &sk, &wopbs_key, wopbs_params);

    //     lut.update(1, 0);

    //     // let lut_at_0 = apply_lut(&ck.as_ref().encrypt_radix(0u64, 4));
    //     let lut_at_1 = lut.apply(&sk.create_trivial_radix(1u64, 4));
    //     let lut_at_2 = lut.apply(&sk.create_trivial_radix(2u64, 4));
    //     let clear1: u32 = ck.decrypt(&lut_at_1);
    //     let clear2: u32 = ck.decrypt(&lut_at_2);

    //     assert_eq!(clear1, 0);
    //     assert_eq!(clear2, 4);
    // }
}
