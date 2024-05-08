//! Handles how to represent the different types, content, and headers of a database.

use std::fs;
use std::{fs::read_to_string, path::PathBuf, str::FromStr};

use crate::encoding::{encode_signed, encode_string};

/// An enum with one variant for each possible type of a cell's content.
#[derive(Debug, Clone)]
pub enum CellType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    ShortString,
}

impl CellType {
    /// given a type, returns its length when written as a vector of u64
    pub fn len(&self) -> usize {
        match self {
            Self::ShortString => 4,
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
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    ShortString(String),
}

pub fn clear_record_to_string(record: Vec<CellContent>) -> String {
    record
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Returns the type of a given cell content.
impl From<&CellContent> for CellType {
    fn from(content: &CellContent) -> Self {
        match content {
            CellContent::Bool(_) => Self::Bool,
            CellContent::U8(_) => Self::U8,
            CellContent::U16(_) => Self::U16,
            CellContent::U32(_) => Self::U32,
            CellContent::U64(_) => Self::U64,
            CellContent::I8(_) => Self::I8,
            CellContent::I16(_) => Self::I16,
            CellContent::I32(_) => Self::I32,
            CellContent::I64(_) => Self::I64,
            CellContent::ShortString(_) => Self::ShortString,
        }
    }
}

impl CellContent {
    /// Returns a `String` representation of its content.
    #[allow(dead_code)]
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        match self {
            Self::Bool(b) => format!("{b}"),
            Self::U8(u) => format!("{u}"),
            Self::U16(u) => format!("{u}"),
            Self::U32(u) => format!("{u}"),
            Self::U64(u) => format!("{u}"),
            Self::I8(i) => format!("{i}"),
            Self::I16(i) => format!("{i}"),
            Self::I32(i) => format!("{i}"),
            Self::I64(i) => format!("{i}"),
            Self::ShortString(s) => format!("\"{s}\""),
        }
    }
    /// Encode every cell content as a vector of `u64`s. In every cases other than
    /// `ShortString`, it has a length of 1.
    pub fn encode(&self) -> Vec<u64> {
        match self {
            Self::Bool(b) => vec![*b as u64],
            Self::U8(u) => vec![*u as u64],
            Self::U16(u) => vec![*u as u64],
            Self::U32(u) => vec![*u as u64],
            Self::U64(u) => vec![*u],
            Self::I8(i) => vec![encode_signed(*i)],
            Self::I16(i) => vec![encode_signed(*i)],
            Self::I32(i) => vec![encode_signed(*i)],
            Self::I64(i) => vec![encode_signed(*i)],
            Self::ShortString(s) => encode_string(s.to_string()),
        }
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
            CellType::U64 => Self::U64(u64::from_str(arg.0).unwrap()),
            CellType::I8 => Self::I8(i8::from_str(arg.0).unwrap()),
            CellType::I16 => Self::I16(i16::from_str(arg.0).unwrap()),
            CellType::I32 => Self::I32(i32::from_str(arg.0).unwrap()),
            CellType::I64 => Self::I64(i64::from_str(arg.0).unwrap()),
            CellType::ShortString => Self::ShortString(String::from(arg.0)),
        }
    }
}

/// A struct holding a vector of tuples `(column_identifier, data_type)`.
#[derive(Clone, Debug)]
pub struct TableHeaders(pub Vec<(String, CellType)>);

impl TableHeaders {
    /// Given a column identifier, returns its type.
    pub fn type_of(&self, column: String) -> Result<CellType, String> {
        for (label, cell_type) in self.0.iter() {
            if label == &column {
                return Ok(cell_type.clone());
            }
        }
        Err(format!("column '{column}' does not exist"))
    }

    /// Given a column identifier, returns the index of its first element. Each element is of type
    /// u64, so an column of type u64 has 1 associated index, a column of type ShortString has 8, etc.
    pub fn index_of(&self, column: String) -> Result<u8, String> {
        let mut result: usize = 0;
        for (label, cell_type) in self.0.iter() {
            if label == &column {
                return Ok(result as u8);
            }
            result += cell_type.len();
        }
        Err(format!("column '{column}' does not exist"))
    }

    pub fn len(&self) -> usize {
        self.0.iter().map(|(_, cell_type)| cell_type.len()).sum()
    }
}

/// A representation of a SQL table.
#[derive(Clone, Debug)]
pub struct Table {
    pub headers: TableHeaders,
    pub content: Vec<Vec<CellContent>>,
}

/// A list of pairs `(table_name, headers)`.
pub struct DatabaseHeaders(pub Vec<(String, TableHeaders)>);

/// A vector of tuples `(table_name, table)`.
pub struct Database {
    pub tables: Vec<(String, Table)>,
}

impl DatabaseHeaders {
    /// Maps a table name to its index in the vector.
    pub fn table_index(&self, table_name: String) -> u8 {
        for (i, (name, _)) in self.0.iter().enumerate() {
            if name == &table_name {
                return i as u8;
            }
        }
        panic!(
            "table {table_name} not found in: {:?}",
            self.0.iter().map(|(name, _)| name).collect::<Vec<_>>()
        )
    }
}

impl Database {
    /// Outputs a list of table headers found in the database.
    pub fn headers(&self) -> DatabaseHeaders {
        DatabaseHeaders(
            self.tables
                .iter()
                .map(|(s, t)| (s.clone(), t.headers.clone()))
                .collect::<Vec<_>>(),
        )
    }
}

/// Parse headers of a csv file.
fn read_headers(path: PathBuf) -> TableHeaders {
    let header = read_to_string(path)
        .unwrap()
        .lines()
        .map(String::from)
        .next()
        .unwrap()
        .clone();
    let mut result: Vec<(String, CellType)> = Vec::new();
    let header_split = header.split(',');
    for column in header_split {
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
pub fn load_tables(path: PathBuf) -> Result<Database, Box<dyn std::error::Error>> {
    let mut result: Vec<(String, Table)> = Vec::new();
    let db_path = fs::read_dir(path).expect("Database path error: can't read directory {path}");
    for table_file in db_path {
        let table_path = table_file?.path();
        let table_name: String = table_path
            .file_stem()
            .and_then(|f| f.to_str().map(String::from))
            .expect("file name error {table_path}");

        let headers = read_headers(table_path.clone());
        let mut rdr = csv::Reader::from_path(table_path)?;
        let mut content: Vec<Vec<CellContent>> = Vec::new();

        for record in rdr.records() {
            let mut record_content: Vec<CellContent> = Vec::with_capacity(headers.0.len());
            let inner_record = record.unwrap();
            let cell_iter = inner_record.iter().zip(headers.0.clone());
            for (content, (_label, cell_type)) in cell_iter {
                record_content.push(CellContent::from((content, &cell_type)));
            }
            content.push(record_content);
        }
        result.push((table_name, Table { headers, content }))
    }
    Ok(Database { tables: result })
}
