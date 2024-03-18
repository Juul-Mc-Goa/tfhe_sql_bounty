use std::fs;
use std::{fs::read_to_string, path::PathBuf, str::FromStr};
use tfhe::integer::wopbs::WopbsKey;
use tfhe::integer::{ClientKey, IntegerCiphertext, RadixCiphertext, ServerKey};
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
        server_key: ServerKey,
        wopbs_key: WopbsKey,
    ) -> Ciphertext {
        if query.is_empty() {
            return server_key.create_trivial_radix(1, 1);
        }
        let entry_length = entry.len();
        // use PBS to map an encrypted index to an encrypted value, via the `map` method
        // TODO use WopbsKey::generate_lut_radix()
        // REVIEW generate_lut_radix takes a ciphertext and a fn as inputs ??
        let f = |u: u64| -> u64 {
            let v = u as usize;
            if v < entry_length {
                entry[v] as u64
            } else {
                0
            }
        };
        // convenience closure for adding bools
        let add_bool = |b1: Ciphertext, b2: Ciphertext| -> Ciphertext {
            server_key
                .unchecked_add_parallelized(
                    &RadixCiphertext::from_blocks(vec![b1]),
                    &RadixCiphertext::from_blocks(vec![b2]),
                )
                .blocks()[0]
                .clone()
        };
        // convenience closure for multiplying bools
        let mul_bool = |b1: Ciphertext, b2: Ciphertext| -> Ciphertext {
            server_key
                .unchecked_mul_parallelized(
                    &RadixCiphertext::from_blocks(vec![b1]),
                    &RadixCiphertext::from_blocks(vec![b2]),
                )
                .blocks()[0]
                .clone()
        };
        // run an encrypted atomic query
        let compute_atom = |current_val: RadixCiphertext, encrypted_atom: &EncryptedAtom| {
            let (_, val, is_leq, negate) = encrypted_atom;

            add_bool(
                add_bool(
                    mul_bool(
                        is_leq.clone(),
                        server_key.lt_parallelized(&current_val, val).into_inner(),
                    ),
                    server_key.eq_parallelized(&current_val, val).into_inner(),
                ),
                negate.clone(),
            )
        };

        // Use FheUint2 so that XOR becomes addition mod 2 (the MSB of the result
        // is ignored)
        let mut result_bool = FheUint2::encrypt_trivial(0u32);
        let mut current_and_clause = compute_atom(
            FheUint32::cast_from(query[0].1 .0.clone()).map(f),
            &query[0].1,
        );
        for (op, encrypted_atom) in query {
            let index = encrypted_atom.0.clone();
            let op_as_uint2 = FheUint2::cast_from(op.clone());
            let current_val = FheUint32::cast_from(index).map(f);
            let atom_bool = compute_atom(current_val, encrypted_atom);
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
            result_bool =
                &result_bool + (1 + &op_as_uint2) * &current_and_clause * (1 + &result_bool);
            // current_and_clause:
            //   | if op: (current_and_clause AND atom_bool)
            //   | else: atom_bool
            // so we get:
            // current_and_clause = (op AND (current_and_clause AND atom_bool)) XOR (!op AND atom_bool)
            // and compute modulo 2:
            // current_and_clause = (op * current_and_clause * atom_bool) + (1 + op) * atom_bool
            //                    = atom_bool * (1 + op * (1 + current_and_clause))
            current_and_clause = atom_bool * (1 + &op_as_uint2 * (1 + current_and_clause));
        }
        (result_bool % 2).ne(&FheUint2::encrypt_trivial(0u16))
    }
    pub fn run_fhe_query(
        &self,
        query: EncryptedSyntaxTree,
        server_key: ServerKey,
    ) -> Vec<Ciphertext> {
        // iterate through each entry
        self.content
            .iter()
            .map(|entry| self.run_query_on_entry(entry, &query, server_key))
            .collect()
    }
}

/// A vector of tuples `(table_name, table)`.
pub struct Tables {
    pub server_key: ServerKey,
    pub wopbs_key: WopbsKey,
    pub tables: Vec<(String, Table)>,
}

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
    server_key: &ServerKey,
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
    Ok(Tables(result))
}
