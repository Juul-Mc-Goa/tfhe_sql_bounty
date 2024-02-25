use sqlparser::ast::{BinaryOperator, Expr, Ident, SetExpr, Statement, UnaryOperator, Value};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use std::{fs::read_to_string, path::PathBuf, str::FromStr};
use tfhe::prelude::*;
use tfhe::shortint::{ClassicPBSParameters, MultiBitPBSParameters};
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint8};

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

const NON_MULTI_BIT: ClassicPBSParameters =
    tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
const MULTI_BIT_2: MultiBitPBSParameters =
    tfhe::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS;
const MULTI_BIT_3: MultiBitPBSParameters =
    tfhe::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS;

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

impl From<&str> for CellType {
    fn from(str_type: &str) -> Self {
        match str_type {
            "bool" => CellType::Bool,
            "uint8" => CellType::U8,
            "uint16" => CellType::U16,
            "uint32" => CellType::U32,
            "int8" => CellType::I8,
            "int16" => CellType::I16,
            "int32" => CellType::I32,
            "string" => CellType::ShortString,
            _ => panic!("Unknown data type: {str_type}"),
        }
    }
}

impl From<(&str, &CellType)> for CellContent {
    fn from(arg: (&str, &CellType)) -> Self {
        match arg.1 {
            CellType::Bool => CellContent::Bool(bool::from_str(arg.0).unwrap()),
            CellType::U8 => CellContent::U8(u8::from_str(arg.0).unwrap()),
            CellType::U16 => CellContent::U16(u16::from_str(arg.0).unwrap()),
            CellType::U32 => CellContent::U32(u32::from_str(arg.0).unwrap()),
            CellType::I8 => CellContent::I8(i8::from_str(arg.0).unwrap()),
            CellType::I16 => CellContent::I16(i16::from_str(arg.0).unwrap()),
            CellType::I32 => CellContent::I32(i32::from_str(arg.0).unwrap()),
            CellType::ShortString => CellContent::ShortString(String::from(arg.0)),
        }
    }
}

fn read_header(path: PathBuf) -> Vec<(String, CellType)> {
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
    // println!("header: {result:?}");
    result
}

/// An atomic logic relation of the form `column OP value`:
/// - the `String` contains the name of the column being tested,
/// - the `CellContent` contains the value against which it is tested.
enum LogicRelation {
    LessThan(String, CellContent),
    LessEqual(String, CellContent),
    Equal(String, CellContent),
    GreaterEqual(String, CellContent),
    GreaterThan(String, CellContent),
    NotEqual(String, CellContent),
}

enum QuerySyntaxTree {
    And(Box<QuerySyntaxTree>, Box<QuerySyntaxTree>),
    Or(Box<QuerySyntaxTree>, Box<QuerySyntaxTree>),
    Not(Box<QuerySyntaxTree>),
    Atom(LogicRelation),
}

impl From<(Ident, BinaryOperator, Value)> for LogicRelation {
    fn from(sqlparser_term: (Ident, BinaryOperator, Value)) -> Self {
        let ident = sqlparser_term.0.value;
        let val = match sqlparser_term.2 {
            Value::Number(n, _b) => CellContent::U32(u32::from_str(&n).unwrap()),
            Value::UnQuotedString(s) | Value::SingleQuotedString(s) => CellContent::ShortString(s),
            Value::Boolean(b) => CellContent::Bool(b),
            _ => panic!("unknown value: {:?}", sqlparser_term.2),
        };
        match sqlparser_term.1 {
            BinaryOperator::Lt => LogicRelation::LessThan(ident, val),
            BinaryOperator::LtEq => LogicRelation::LessEqual(ident, val),
            BinaryOperator::Eq => LogicRelation::Equal(ident, val),
            BinaryOperator::GtEq => LogicRelation::GreaterEqual(ident, val),
            BinaryOperator::Gt => LogicRelation::GreaterThan(ident, val),
            BinaryOperator::NotEq => LogicRelation::NotEqual(ident, val),
            _ => panic!("unknown operator: {:?}", sqlparser_term.1),
        }
    }
}

impl From<Expr> for QuerySyntaxTree {
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
                    QuerySyntaxTree::Atom(LogicRelation::from((i_left, op.to_owned(), v_right)))
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
                    _ => panic!("unknown expresion: {op}"),
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

fn build_cnf(statement: Statement) -> QuerySyntaxTree {
    match statement {
        Statement::Query(q) => match q.body.as_ref() {
            SetExpr::Select(s) => QuerySyntaxTree::from(s.selection.clone().unwrap()),
            _ => panic!("unknown query: {q:?}"),
        },
        _ => panic!("unknown statement: {statement:?}"),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default()
        .use_custom_parameters(NON_MULTI_BIT, None)
        .build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);

    let clear_a = 1344u32;
    let clear_b = 5u32;
    let clear_c = 7u8;

    // Encrypting the input data using the (private) client_key
    // FheUint32: Encrypted equivalent to u32
    let mut encrypted_a = FheUint32::try_encrypt(clear_a, &client_key)?;
    let encrypted_b = FheUint32::try_encrypt(clear_b, &client_key)?;

    // FheUint8: Encrypted equivalent to u8
    let encrypted_c = FheUint8::try_encrypt(clear_c, &client_key)?;

    // On the server side:
    set_server_key(server_keys);

    // Clear equivalent computations: 1344 * 5 = 6720
    let encrypted_res_mul = &encrypted_a * &encrypted_b;

    // Clear equivalent computations: 1344 >> 5 = 42
    encrypted_a = &encrypted_res_mul >> &encrypted_b;

    // Clear equivalent computations: let casted_a = a as u8;
    let casted_a: FheUint8 = encrypted_a.cast_into();

    // Clear equivalent computations: min(42, 7) = 7
    let encrypted_res_min = &casted_a.min(&encrypted_c);

    // Operation between clear and encrypted data:
    // Clear equivalent computations: 7 & 1 = 1
    let encrypted_res = encrypted_res_min & 1_u8;

    // Decrypting on the client side:
    let clear_res: u8 = encrypted_res.decrypt(&client_key);
    assert_eq!(clear_res, 1_u8);

    let table_path = "db_dir/table_2.csv";
    let header_labels_and_types = read_header(table_path.into());
    let mut rdr = csv::Reader::from_path(table_path)?;
    let mut table_content: Vec<Vec<CellContent>> = Vec::new();
    for entry in rdr.records() {
        let mut entry_content: Vec<CellContent> = Vec::with_capacity(header_labels_and_types.len());
        let inner_entry = entry.unwrap();
        let cell_iter = inner_entry.iter().zip(header_labels_and_types.clone());
        for (content, (_label, cell_type)) in cell_iter {
            entry_content.push(CellContent::from((content, &cell_type)));
        }
        table_content.push(entry_content);
    }
    // println!("{table_content:?}");
    let query_path = "query.txt";
    let selection = parse_query(query_path.into());
    match selection {
        Statement::Query(q) => println!("{:?}", q),
        _ => panic!(),
    }
    // println!("{:?}", parse_query(query_path.into()));
    Ok(())
}
