use std::fs;
use std::{fs::read_to_string, path::PathBuf, str::FromStr};
use tfhe::integer::wopbs::WopbsKey;
use tfhe::integer::{ClientKey, IntegerCiphertext, RadixCiphertext, ServerKey};
use tfhe::shortint::{Ciphertext, WopbsParameters};

use crate::cipher_structs::{EntryLUT, FheBool, QueryLUT};
use crate::encoding::{encode_signed, encode_string};
use crate::EncryptedSyntaxTree;

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
            Self::ShortString(s) => s.clone(),
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
            Self::U64(u) => vec![*u as u64],
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
}

/// A representation of a SQL table.
#[derive(Clone, Debug)]
pub struct Table {
    pub headers: TableHeaders,
    pub content: Vec<Vec<CellContent>>,
}

/// An encoded representation of a SQL table.
///
/// Each entry is stored as a `Vec<u64>`. A table is a vector of entries.
// #[derive(Debug)]
pub struct TableQueryRunner<'a> {
    pub content: Vec<Vec<u64>>,
    pub client_key: &'a ClientKey,
    pub server_key: &'a ServerKey,
    pub wopbs_key: &'a WopbsKey,
    pub wopbs_parameters: WopbsParameters,
}

impl<'a> TableQueryRunner<'a> {
    pub fn new(
        table: Table,
        client_key: &'a ClientKey,
        server_key: &'a ServerKey,
        wopbs_key: &'a WopbsKey,
        wopbs_parameters: WopbsParameters,
    ) -> Self {
        Self {
            content: table
                .content
                .iter()
                .map(|entry| entry.iter().map(|cell| cell.encode()).flatten().collect())
                .collect::<Vec<Vec<u64>>>(),
            client_key,
            server_key,
            wopbs_key,
            wopbs_parameters,
        }
    }

    /// Runs an encrypted query on a given entry.
    ///
    /// # Inputs
    /// - `entry: &Vec<u64>` an encoded entry,
    /// - `query: &EncryptedSyntaxTree` an encrypted `SELECT` query,
    /// - `query_lut: &mut QueryLUT` an updatable, hidden lookup table.
    /// # Output
    /// A `Ciphertext` encrypting a boolean that answers the question: "Is this
    /// entry selected by the query?"
    ///
    /// The encrypted boolean is actually an integer modulo 2, so that:
    /// - `a AND b` becomes `a*b`,
    /// - `a XOR b` becomes `a+b`,
    /// - `a OR b` becomes `a+b+a*b`,
    /// - `NOT a` becomes `1+a`.
    ///
    /// Then the boolean formulas are simplified so as to minimize the number of
    /// multiplications, using the fact that addition is much faster than PBS.
    /// We also use that:
    ///
    /// $(a \lt b) \text{ XOR } (a = b) \iff a \leq b$.
    ///
    /// # Simplification of the boolean formulas:
    ///
    /// We first write:
    /// ```
    /// result_bool:
    ///   | if is_node: node_bool XOR negate
    ///   | else:       atom_bool XOR negate
    /// node_bool:
    ///   | if which_op: atom_left OR  atom_right
    ///   | else:        atom_left AND atom_right
    /// atom_bool:
    ///   | if which_op: val_left <= val_right
    ///   | else:        val_left == val_right
    /// ```
    /// and translate these definition into boolean formulas:
    /// ```
    /// result_bool = (is_node  AND node_bool) XOR
    ///               (!is_node AND atom_bool) XOR
    ///               negate
    /// node_bool = (which_op  AND (atom_left OR  atom_right)) XOR
    ///             (!which_op AND (atom_left AND atom_right))
    /// atom_bool = (which_op  AND (val_left <= val_right)) XOR
    ///             (!which_op AND (val_left == val_right))
    /// ```
    /// Let `is_lt, is_eq` be the two boolean result of `val_left < val_right`
    /// and `val_left == val_right`.  We compute modulo 2:
    /// ```
    /// node_bool = which_op       * (atom_left + atom_right + atom_left * atom_right) +
    ///             (1 + which_op) * atom_left * atom_right
    ///           = atom_left * atom_right + which_op * (atom_left + atom_right)
    /// ```
    /// ```
    /// atom_bool = which_op       * (is_lt + is_eq) +
    ///             (1 + which_op) * is_eq
    ///           = is_eq + which_op * is_lt
    /// ```
    /// So we get:
    /// ```
    /// result_bool = is_node       * (atom_left * atom_right + which_op * (atom_left + atom_right)) +
    ///               (1 + is_node) * (is_eq + which_op * is_lt) +
    ///               negate
    ///
    /// ```
    /// This uses 5 multiplications. We can reduce to 4 by:
    /// 1. distributing the product `(1 + is_node) * B => B + is_node * B`,
    /// 2. factorising by `is_node`,
    /// 3. factorising by `which_op`.
    /// ```
    /// result_bool = is_node * (
    ///                 atom_left * atom_right +
    ///                 is_eq +
    ///                 which_op * (atom_left + atom_right + is_lt)) +
    ///               is_eq + which_op * lt +
    ///               negate
    /// ```
    /// Thus only 4 multiplications are required.
    ///
    /// # Total number of PBS required
    /// 1. One for retrieving the value associated to an encrypted column identifier,
    /// 2. Two for evaluating `is_eq` and `is_lt`,
    /// 3. Two for retrieving `atom_left` and `atom_right`,
    /// 4. Four for computing `result_bool`.
    ///
    /// So a total of 9 PBS for each `EncryptedInstruction`.
    fn run_query_on_entry(
        &self,
        entry: &Vec<u64>,
        query: &EncryptedSyntaxTree,
        query_lut: &mut QueryLUT,
    ) -> Ciphertext {
        println!("\n*** NEW ENTRY ***");
        let sk = self.server_key;

        let entry_lut = EntryLUT::new(entry, sk, self.wopbs_key);

        let new_fhe_bool = |ct: Ciphertext| FheBool { ct, server_key: sk };
        let mut result_bool = FheBool::encrypt_trivial(true, sk);

        let is_lt = |a: &RadixCiphertext, b: &RadixCiphertext| -> FheBool {
            new_fhe_bool(sk.lt_parallelized(a, b).into_inner())
        };

        let is_eq = |a: &RadixCiphertext, b: &RadixCiphertext| -> FheBool {
            new_fhe_bool(sk.eq_parallelized(a, b).into_inner())
        };

        if query.is_empty() {
            // if the query is empty then return true
            return result_bool.ct;
        }

        // let decrypt_bool = |ct: &FheBool| self.client_key.decrypt_one_block(&ct.ct);
        // let decrypt_radix = |ct: &RadixCiphertext| self.client_key.decrypt_radix::<u64>(ct);

        // else, loop through all atoms
        for (index, (is_node, left, which_op, right, negate)) in query.iter().enumerate() {
            println!("atom n°{index}...");

            let (is_node, which_op, negate) = (
                new_fhe_bool(is_node.clone()),
                new_fhe_bool(which_op.clone()),
                new_fhe_bool(negate.clone()),
            );

            let val_left = entry_lut.apply(left);
            let val_right = right;
            // (val_left <= val_right) <=> is_lt XOR is_eq
            let is_lt = is_lt(&val_left, val_right);
            let is_eq = is_eq(&val_left, val_right);
            let atom_left = new_fhe_bool(query_lut.apply(left));
            let atom_right = new_fhe_bool(query_lut.apply(&sk.cast_to_unsigned(right.clone(), 4)));

            result_bool = is_node
                * (&(&atom_left * &atom_right)
                    + &is_eq
                    + &which_op * &(&(atom_left + atom_right) + &is_lt))
                + is_eq
                + which_op * is_lt
                + negate;

            // enforce that result_bool encrypts either 0 or 1
            // result_bool = new_fhe_bool(result_bool.into_boolean_block().into_inner());

            query_lut.update(index as u8, result_bool.ct.clone());
        }
        result_bool.ct
    }

    pub fn run_fhe_query(&self, query: &EncryptedSyntaxTree) -> Vec<Ciphertext> {
        let inner_sk = self.server_key.clone().into_raw_parts();
        let inner_wopbs = self.wopbs_key.clone().into_raw_parts();

        let mut query_lut: QueryLUT<'_> = QueryLUT::new(
            query.len(),
            &inner_sk,
            &inner_wopbs,
            self.wopbs_parameters.clone(),
        );
        let mut result: Vec<Ciphertext> = Vec::with_capacity(self.content.len());
        // iterate through each entry
        for entry in self.content.iter() {
            result.push(self.run_query_on_entry(entry, query, &mut query_lut));
            query_lut.flush();
        }

        result
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

#[cfg(test)]
mod tests {
    // use super::*;
    // use crate::generate_keys;
}
