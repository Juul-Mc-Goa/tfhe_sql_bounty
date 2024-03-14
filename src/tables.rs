use std::fs;
use std::{fs::read_to_string, path::PathBuf, str::FromStr};
use tfhe::prelude::*;
use tfhe::{ClientKey, FheUint32};

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
        match self {
            Self::Bool(b) => vec![*b as u32],
            Self::U8(u) => vec![*u as u32],
            Self::U16(u) => vec![*u as u32],
            Self::U32(u) => vec![*u as u32],
            Self::I8(i) => vec![*i as u32],
            Self::I16(i) => vec![*i as u32],
            Self::I32(i) => vec![*i as u32],
            Self::ShortString(s) => {
                let s_len = s.len();
                let s_bytes = s.as_bytes();
                let mut result: Vec<u32> = Vec::new();
                for i in 0..8 {
                    let j = 4 * i;
                    let (b0, b1, b2, b3) = (
                        if j < s_len { s_bytes[j] } else { 0u8 } as u32,
                        if j + 1 < s_len { s_bytes[j + 1] } else { 0u8 } as u32,
                        if j + 2 < s_len { s_bytes[j + 2] } else { 0u8 } as u32,
                        if j + 3 < s_len { s_bytes[j + 3] } else { 0u8 } as u32,
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
    pub fn encrypt(&self, client_key: &ClientKey) -> Vec<FheUint32> {
        self.encode()
            .iter()
            .map(|u| FheUint32::encrypt(*u, client_key))
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
#[derive(Debug)]
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
    fn type_of(&self, column: String) -> Result<CellType, String> {
        for (label, cell_type) in self.0.iter() {
            if label == &column {
                return Ok(cell_type.clone());
            }
        }
        Err(format!("column '{column}' does not exist"))
    }
}

/// A representation of a SQL table.
#[derive(Debug)]
pub struct Table {
    pub headers: TableHeaders,
    pub content: Vec<Vec<CellContent>>,
}

/// A vector of tuples `(table_name, table)`.
pub struct Tables(pub Vec<(String, Table)>);

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

/// Loads a directory with a structure described above in a format
/// that works for your implementation of the encryted query
pub fn load_tables(path: PathBuf) -> Result<Tables, Box<dyn std::error::Error>> {
    let mut result: Vec<(String, Table)> = Vec::new();
    let db_path = fs::read_dir(path).expect("Database path error: can't read directory {path}");
    for table_direntry in db_path {
        let table_path = table_direntry?.path();
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
