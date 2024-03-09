use sqlparser::ast::{BinaryOperator, Expr, Ident, SetExpr, Statement, UnaryOperator, Value};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use std::fs;
use std::{fs::read_to_string, path::PathBuf, str::FromStr};
use tfhe::boolean::client_key;
use tfhe::shortint::PBSParameters;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint32, FheUint8};
use tfhe::{prelude::*, FheUint};

#[derive(Debug, Clone)]
enum CellType {
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
    /// given a type, returns its length when written as a vector of u8
    fn len(&self) -> usize {
        match self {
            Self::Bool | Self::U8 | Self::I8 => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 => 4,
            Self::ShortString => 32,
        }
    }
}

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

#[derive(Debug)]
enum CellContent {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    I8(i8),
    I16(i16),
    I32(i32),
    ShortString(String),
}

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
    fn len(&self) -> usize {
        CellType::from(self).len()
    }
    fn encrypt(&self, client_key: &ClientKey) -> Vec<FheUint8> {
        let mut result = Vec::<FheUint8>::new();
        let mut push_u8 = |u: u8| result.push(FheUint8::try_encrypt(u, client_key).unwrap());
        let mut push_u16 = |u: u16| {
            push_u8((u >> 8) as u8);
            push_u8((u % 256) as u8);
        };
        let mut push_u32 = |u: u32| {
            push_u16(((u >> 16) % (1 << 16)) as u16);
            push_u16((u % (1 << 16)) as u16);
        };
        match self {
            Self::Bool(b) => result.push(if *b {
                FheUint8::try_encrypt(1u8, client_key).unwrap()
            } else {
                FheUint8::try_encrypt(0u8, client_key).unwrap()
            }),
            Self::U8(u) => push_u8(*u),
            Self::U16(u) => push_u16(*u),
            Self::U32(u) => push_u32(*u),
            Self::I8(i) => push_u8(*i as u8),
            Self::I16(i) => push_u16(*i as u16),
            Self::I32(i) => push_u32(*i as u32),
            Self::ShortString(s) => {
                let s_len = s.len();
                let s_bytes = s.as_bytes();
                for i in 0..32 {
                    if i + 1 > s_len {
                        result.push(FheUint8::encrypt(0u8, client_key))
                    } else {
                        result.push(FheUint8::encrypt(s_bytes[i], client_key))
                    }
                }
            }
        }
        result
    }
}

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

#[derive(Debug)]
struct TableHeaders(Vec<(String, CellType)>);

impl TableHeaders {
    fn index_of(&self, column: String) -> Result<u8, String> {
        for (i, (label, _cell_type)) in self.0.iter().enumerate() {
            if label == &column {
                return Ok(i as u8);
            }
        }
        Err("column \"{column}\" does not exist".into())
    }
    fn type_of(&self, column: String) -> Result<CellType, String> {
        for (label, cell_type) in self.0.iter() {
            if label == &column {
                return Ok(cell_type.clone());
            }
        }
        Err("column \"{column}\" does not exist".into())
    }
}

#[derive(Debug)]
struct Table {
    headers: TableHeaders,
    content: Vec<Vec<CellContent>>,
}

struct Tables(Vec<(String, Table)>);

fn read_header(path: PathBuf) -> TableHeaders {
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

#[derive(Debug)]
enum ComparisonOp {
    LessThan,
    LessEqual,
    Equal,
    GreaterEqual,
    GreaterThan,
    NotEqual,
}

impl ComparisonOp {
    /// Each comparison is encoded as a small unsigned integer which is then encrypted with the
    /// client key.
    fn index(&self) -> u8 {
        match &self {
            Self::LessThan => 0,
            Self::LessEqual => 1,
            Self::Equal => 2,
            Self::GreaterEqual => 3,
            Self::GreaterThan => 4,
            Self::NotEqual => 5,
        }
    }
}

impl From<BinaryOperator> for ComparisonOp {
    fn from(other: BinaryOperator) -> Self {
        match other {
            BinaryOperator::Lt => ComparisonOp::LessThan,
            BinaryOperator::LtEq => ComparisonOp::LessEqual,
            BinaryOperator::Eq => ComparisonOp::Equal,
            BinaryOperator::GtEq => ComparisonOp::GreaterEqual,
            BinaryOperator::Gt => ComparisonOp::GreaterThan,
            BinaryOperator::NotEq => ComparisonOp::NotEqual,
            _ => panic!("unknown operator: {:?}", other),
        }
    }
}

/// An atomic condition of the form `column OP value`:
/// - the `String` contains the name of the column being tested,
/// - the `CellContent` contains the value against which it is tested.
#[derive(Debug)]
struct AtomicCondition {
    ident: String,
    op: ComparisonOp,
    value: CellContent,
}

impl AtomicCondition {
    /// Extracts the type of a cell (int, unsigned int, or short string). Used in the `len` method.
    fn column_type(&self) -> CellType {
        CellType::from(&self.value)
    }
    /// Computes the number of u8 needed to encode an atomic condition `column OP value`
    fn len(&self) -> usize {
        // one u8 for identifying the column
        // one u8 for storing the comparison operator
        // plus some u8 for storing the value to the right of the comparison
        1 + 1 + self.column_type().len()
    }
    /// Encodes itself into a vector of u8, then encrypts the resulting vector.
    /// `client_key` is used for encryption,
    /// `headers` is used to get an `u8` from a column identifier.
    fn encrypt(&self, client_key: &ClientKey, headers: TableHeaders) -> Vec<FheUint8> {
        let mut result = Vec::<FheUint8>::with_capacity(self.len());

        let (encrypted_ident, encrypted_op, mut encrypted_val) = (
            FheUint8::try_encrypt(headers.index_of(self.ident.clone()).unwrap(), client_key)
                .unwrap(),
            FheUint8::try_encrypt(self.op.index(), client_key).unwrap(),
            self.value.encrypt(&client_key),
        );

        result.push(encrypted_ident);
        result.push(encrypted_op);
        result.append(&mut encrypted_val);
        result
    }
}

/// A simple enum holding the syntax tree to the right of the `WHERE` keyword
#[derive(Debug)]
enum WhereSyntaxTree {
    Atom(AtomicCondition),
    Not(Box<WhereSyntaxTree>),
    And(Box<WhereSyntaxTree>, Box<WhereSyntaxTree>),
    Or(Box<WhereSyntaxTree>, Box<WhereSyntaxTree>),
}

impl From<(Ident, BinaryOperator, Value)> for AtomicCondition {
    fn from(sqlparser_term: (Ident, BinaryOperator, Value)) -> Self {
        let ident = sqlparser_term.0.value;
        let op = ComparisonOp::from(sqlparser_term.1);
        let value = match sqlparser_term.2 {
            Value::Number(n, _b) => CellContent::U32(u32::from_str(&n).unwrap()),
            Value::UnQuotedString(s) | Value::SingleQuotedString(s) => CellContent::ShortString(s),
            Value::Boolean(b) => CellContent::Bool(b),
            _ => panic!("unknown value: {:?}", sqlparser_term.2),
        };
        Self { ident, op, value }
    }
}

impl From<(Ident, BinaryOperator, Ident)> for AtomicCondition {
    fn from(sqlparser_term: (Ident, BinaryOperator, Ident)) -> Self {
        let ident = sqlparser_term.0.value;
        let op = ComparisonOp::from(sqlparser_term.1);
        let value = CellContent::ShortString(sqlparser_term.2.value);
        Self { ident, op, value }
    }
}

impl From<Expr> for WhereSyntaxTree {
    fn from(expr: Expr) -> Self {
        match expr {
            Expr::Nested(e) => Self::from(e.as_ref().to_owned()),
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr: e,
            } => Self::Not(Box::new(Self::from(e.as_ref().to_owned()))),
            Expr::UnaryOp { op, .. } => panic!("unknown unary operator {op:?}"),
            Expr::BinaryOp {
                ref left,
                ref op,
                ref right,
            } => match (left.as_ref().to_owned(), right.as_ref().to_owned()) {
                // builds an Atom from a SQL expression `column OP value`
                (Expr::Identifier(i_left), Expr::Value(v_right)) => {
                    WhereSyntaxTree::Atom(AtomicCondition::from((i_left, op.to_owned(), v_right)))
                }
                (Expr::Identifier(i_left), Expr::Identifier(i_right))
                    if op == &BinaryOperator::Eq =>
                {
                    WhereSyntaxTree::Atom(AtomicCondition::from((i_left, op.to_owned(), i_right)))
                }
                // recursively builds a syntax tree from a SQL expression `l OP r`
                // where OP is one of AND, OR
                // and l, r are SQL expressions
                (l, r) => match op {
                    BinaryOperator::And => {
                        Self::And(Box::new(Self::from(l)), Box::new(Self::from(r)))
                    }
                    BinaryOperator::Or => {
                        Self::Or(Box::new(Self::from(l)), Box::new(Self::from(r)))
                    }
                    _ => panic!("unknown expression: {l} {op} {r}"),
                },
            },
            _ => todo!(),
        }
    }
}

fn parse_query(path: PathBuf) -> Statement {
    let dialect = GenericDialect {};
    let str_query = read_to_string(path).unwrap();
    let ast = Parser::parse_sql(&dialect, &str_query).unwrap();
    ast[0].clone()
}

fn build_where_syntax_tree(statement: Statement) -> WhereSyntaxTree {
    match statement {
        Statement::Query(q) => match q.body.as_ref() {
            SetExpr::Select(s) => WhereSyntaxTree::from(s.selection.clone().unwrap()),
            _ => panic!("unknown query: {q:?}"),
        },
        _ => panic!("unknown statement: {statement:?}"),
    }
}

fn default_cpu_parameters() -> PBSParameters {
    PBSParameters::PBS(tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS)
}

// fn encrypt_query(query: sqlparser::ast::Select) -> EncryptedQuery;

/// Loads a directory with a structure described above in a format
/// that works for your implementation of the encryted query
fn load_tables(path: PathBuf) -> Result<Tables, Box<dyn std::error::Error>> {
    let mut result: Vec<(String, Table)> = Vec::new();
    let db_path = fs::read_dir(path).expect("Database path error: can't read directory {path}");
    for table_direntry in db_path {
        let table_path = table_direntry?.path();
        let table_name: String = table_path
            .file_stem()
            .and_then(|f| f.to_str().map(|os_str| String::from(os_str)))
            .expect("file name error {table_path}");
        let headers = read_header(table_path.clone());
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

/// # Inputs:
/// - sks: The server key to use
/// - input: your EncryptedQuery
/// - tables: the plain data you run the query on
///
/// # Output
/// - EncryptedResult
// fn run_fhe_query(
//     sks: &tfhe::integer::ServerKey,
//     input: &EncryptedQuery,
//     data: &Tables,
// ) -> EncryptedResult;

/// The output of this function should be a string using the CSV format
/// You should provide a way to compare this string with the output of
/// the clear DB system you use for comparison
// fn decrypt_result(clientk_key: &ClientKey, result: &EncryptedResult) -> String;

fn decrypt_vec(v: Vec<FheUint8>, client_key: &ClientKey) -> Vec<u8> {
    v.into_iter()
        .map(|encrypted_u8| encrypted_u8.decrypt(client_key))
        .collect::<Vec<u8>>()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = default_cpu_parameters();
    let config = ConfigBuilder::default()
        .use_custom_parameters(params, None)
        .build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);

    // let clear_a = 1344u32;
    // let clear_b = 5u32;
    // let clear_c = 7u8;

    // // Encrypting the input data using the (private) client_key
    // // FheUint32: Encrypted equivalent to u32
    // let mut encrypted_a = FheUint32::try_encrypt(clear_a, &client_key)?;
    // let encrypted_b = FheUint32::try_encrypt(clear_b, &client_key)?;

    // // FheUint8: Encrypted equivalent to u8
    // let encrypted_c = FheUint8::try_encrypt(clear_c, &client_key)?;

    // // On the server side:
    // set_server_key(server_keys);

    // // Clear equivalent computations: 1344 * 5 = 6720
    // let encrypted_res_mul = &encrypted_a * &encrypted_b;

    // // Clear equivalent computations: 1344 >> 5 = 42
    // encrypted_a = &encrypted_res_mul >> &encrypted_b;

    // // Clear equivalent computations: let casted_a = a as u8;
    // let casted_a: FheUint8 = encrypted_a.cast_into();

    // // Clear equivalent computations: min(42, 7) = 7
    // let encrypted_res_min = &casted_a.min(&encrypted_c);

    // // Operation between clear and encrypted data:
    // // Clear equivalent computations: 7 & 1 = 1
    // let encrypted_res = encrypted_res_min & 1_u8;

    // // Decrypting on the client side:
    // let clear_res: u8 = encrypted_res.decrypt(&client_key);
    // assert_eq!(clear_res, 1_u8);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_u8() {
        println!("generating FHE keys...");
        let params = default_cpu_parameters();
        let config = ConfigBuilder::default()
            .use_custom_parameters(params, None)
            .build();

        // Key generation
        let (client_key, _server_keys) = generate_keys(config);
        println!("DONE");
        let content: u8 = 5;
        let cell: CellContent = CellContent::U8(content);
        println!("encrypting content: {cell:?}...");
        let encrypted_cell = cell.encrypt(&client_key);
        println!("decrypting...");
        let decrypted_cell: u8 = encrypted_cell[0].decrypt(&client_key);
        assert_eq!(content, decrypted_cell);
    }

    #[test]
    fn encrypt_short_string() {
        println!("generating FHE keys...");
        let params = default_cpu_parameters();
        let config = ConfigBuilder::default()
            .use_custom_parameters(params, None)
            .build();

        // Key generation
        let (client_key, _server_keys) = generate_keys(config);
        println!("DONE");
        let content: String = "test".into();
        let cell: CellContent = CellContent::ShortString(content.clone());
        println!("encrypting content: {cell:?}...");
        let encrypted_cell = cell.encrypt(&client_key);
        println!("decrypting...");
        let decrypted_cell: Vec<u8> = decrypt_vec(encrypted_cell, &client_key);
        let string_decrypted_cell = std::str::from_utf8(decrypted_cell.as_ref())
            .to_owned()
            .unwrap()
            .trim_matches('\0')
            .to_owned();
        assert_eq!(content, string_decrypted_cell,);
    }

    #[test]
    fn encrypt_atomic_condition() {
        println!("generating FHE keys...");
        let params = default_cpu_parameters();
        let config = ConfigBuilder::default()
            .use_custom_parameters(params, None)
            .build();
        // Key generation
        let (client_key, _server_keys) = generate_keys(config);
        println!("DONE");
        let headers = TableHeaders(vec![(String::from("age"), CellType::U32)]);
        let condition: AtomicCondition = AtomicCondition {
            ident: "age".into(),
            op: ComparisonOp::GreaterEqual,
            value: CellContent::U32(890),
        };
        println!("encrypting condition: {condition:?}...");
        let encrypted_cond = condition.encrypt(&client_key, headers);
        // println!("decrypting...");
        // let decrypted_cond: Vec<u8> = decrypt_vec(encrypted_cond, &client_key);
    }

    #[test]
    fn load_db() {
        let db_dir_path = "db_dir";
        let tables = load_tables(db_dir_path.into()).expect("Failed to load DB at {db_dir_path}");
        let (name0, table0) = &tables.0[0];
        let (name1, table1) = &tables.0[1];
        println!("{name0}\n{table0:?}");
        println!("\n{name1}\n{table1:?}");
    }
}
