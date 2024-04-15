//! Query parsing and manipulation.
//!
//! This module contains types for an internal representation of queries, as
//! well as methods for encoding and encrypting them.

use crate::encoding::*;
use crate::{CellContent, CellType, TableHeaders};

use sqlparser::ast::{BinaryOperator, Expr, Ident, SetExpr, Statement, UnaryOperator, Value};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

use std::{fs::read_to_string, path::PathBuf, str::FromStr};

use tfhe::integer::{ClientKey, RadixCiphertext};
use tfhe::shortint::Ciphertext;

/// Contains one variant for each operator allowed in a `WHERE` expression.
#[derive(Clone, Debug)]
pub enum ComparisonOp {
    LessThan,
    LessEqual,
    Equal,
    GreaterEqual,
    GreaterThan,
    NotEqual,
}

/// An atomic condition of the form `column OP value`:
/// - the `String` contains the identifier of the column being tested,
/// - the `CellContent` contains the value against which it is tested.
#[derive(Clone, Debug)]
pub struct AtomicCondition {
    pub ident: String,
    pub op: ComparisonOp,
    pub value: CellContent,
}

/// A simple enum holding the syntax tree to the right of the `WHERE` keyword.
#[derive(Clone, Debug)]
pub enum WhereSyntaxTree {
    Atom(AtomicCondition),
    And(Box<WhereSyntaxTree>, Box<WhereSyntaxTree>),
    Or(Box<WhereSyntaxTree>, Box<WhereSyntaxTree>),
    Nand(Box<WhereSyntaxTree>, Box<WhereSyntaxTree>),
    Nor(Box<WhereSyntaxTree>, Box<WhereSyntaxTree>),
}

/// An atomic condition of the form `column OP value` where `value` is of type
/// `u32`.
#[derive(Clone, Debug)]
pub struct U64Atom {
    pub index: u8,
    pub op: ComparisonOp,
    pub value: u64,
}

/// A variant of `WhereSyntaxTree` where `AtomicCondition` is replaced by `U32Atom`
#[derive(Clone, Debug)]
pub enum U64SyntaxTree {
    True,
    False,
    Atom(U64Atom),
    And(Box<U64SyntaxTree>, Box<U64SyntaxTree>),
    Or(Box<U64SyntaxTree>, Box<U64SyntaxTree>),
    Nand(Box<U64SyntaxTree>, Box<U64SyntaxTree>),
    Nor(Box<U64SyntaxTree>, Box<U64SyntaxTree>),
}

/// Holds a tuple `(is_node, left, which_op, right, negate)`. Each tuple represents
/// either one `WhereSyntaxTree::Atom` (unless the value type is `ShortString`) or
/// one `WhereSyntaxTree::Node`. Each `Atom` value is encoded as one `u32`, except
/// `ShortString` which is encoded as a eight `u32`s.
///
/// The encoding is made as follows:
/// - `is_node`:
///   - `true`: the tuple encodes a binary `Node`
///     1. `left`: index of the left child,
///     2. `which_op`:
///         - `true`: `OR`,
///         - `false`: `AND`,
///     3. `right`: index of the right child,
///   - `false`: the tuple encodes an `Atom`
///     1. `left`: column identifier,
///     2. `which_op`:
///         - `true`: `<=`,
///         - `false`: `=`,
///     3. `right`: value against which `left` is tested,
/// - `negate`: encodes wether to negate the boolean result of `left which_op
///    right`.
pub type EncodedInstruction = (bool, u8, bool, u32, bool);
pub type EncodedInstruction64 = (bool, u8, bool, u64, bool);

/// Encrypted variant of `EncodedInstruction`.
///
/// Holds a tuple `(is_node, left, which_op, right, negate)`, where:
/// - `is_node` is an encrypted boolean,
/// - `left` is an encrypted u8,
/// - `which_op` is an encrypted boolean,
/// - `right` is an encrypted u32,
/// - `negate` is an encrypted boolean.
pub type EncryptedInstruction = (
    Ciphertext,
    RadixCiphertext,
    Ciphertext,
    RadixCiphertext,
    Ciphertext,
);

/// A type alias for storing (the encryption of) a `WHERE` syntax tree.
///
/// It is a vector of `(CipherText, RadixCipherText, CipherText,
/// RadixCiphertext, CipherText)`, where each tuple represents either an `Atom`
/// or a boolean operator (`AND`, `OR`, `NAND`, `NOR`).
pub type EncryptedSyntaxTree = Vec<EncryptedInstruction>;

/// Translates a `BinaryOperator` from the crate `sqlparser` into a `ComparisonOp`.
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

impl ComparisonOp {
    /// Convenience method for negating a comparison.
    pub fn negate(&mut self) {
        *self = match self {
            ComparisonOp::Equal => ComparisonOp::NotEqual,
            ComparisonOp::NotEqual => ComparisonOp::Equal,
            ComparisonOp::LessEqual => ComparisonOp::GreaterThan,
            ComparisonOp::GreaterThan => ComparisonOp::LessEqual,
            ComparisonOp::LessThan => ComparisonOp::GreaterEqual,
            ComparisonOp::GreaterEqual => ComparisonOp::LessThan,
        }
    }

    /// Creates a `String` representation of a `ComparisonOp` for debugging purposes.
    fn to_string(&self) -> String {
        match self {
            ComparisonOp::Equal => "=",
            ComparisonOp::NotEqual => "!=",
            ComparisonOp::LessEqual => "<=",
            ComparisonOp::GreaterThan => ">",
            ComparisonOp::LessThan => "<",
            ComparisonOp::GreaterEqual => ">=",
        }
        .into()
    }
}

impl U64Atom {
    pub fn negate(&mut self) {
        self.op.negate()
    }

    /// Creates a `String` representation of an atom for debugging purposes.
    fn to_string(&self) -> String {
        format!(
            "{} {} {}",
            self.index.to_string(),
            self.op.to_string(),
            self.value.to_string()
        )
    }

    pub fn encode(&self) -> EncodedInstruction64 {
        let index = self.index;
        let value = self.value;
        let (op, negate, value) = match self.op {
            ComparisonOp::Equal => (false, false, value),
            ComparisonOp::NotEqual => (false, true, value),
            ComparisonOp::LessEqual => (true, false, value),
            ComparisonOp::GreaterThan => (true, true, value), // a > b <=> not(a <= b)
            ComparisonOp::LessThan => (true, false, value - 1), // a < b <=> a <= b-1
            ComparisonOp::GreaterEqual => (true, true, value - 1), // a >= b <=> not(a <= b-1)
        };
        (false, index, op, value, negate)
    }
}

impl U64SyntaxTree {
    /// Stringifies a `U64SyntaxTree` for debugging purposes.
    #[allow(dead_code)]
    fn to_string_lines(&self, base_index: u8) -> Vec<String> {
        let indent_closure =
            |v: Vec<String>| v.iter().map(|s| format!("  {s}")).collect::<Vec<String>>();
        let binary_op_closure = |op: &str, a: &Box<U64SyntaxTree>, b: &Box<U64SyntaxTree>| {
            let b_base_index = a.index(base_index) + 1;
            let mut result = vec![format!("({}) {op}", self.index(base_index))];
            let mut left: Vec<String> = indent_closure(a.to_string_lines(base_index));
            let mut right: Vec<String> = indent_closure(b.to_string_lines(b_base_index));
            result.append(&mut left);
            result.append(&mut right);
            result
        };
        match &self {
            U64SyntaxTree::True => {
                vec![format!("({}) True", self.index(base_index))]
            }
            U64SyntaxTree::False => {
                vec![format!("({}) False", self.index(base_index))]
            }
            U64SyntaxTree::Atom(a) => {
                vec![format!("({}) {}", self.index(base_index), a.to_string())]
            }
            U64SyntaxTree::And(a, b) => binary_op_closure("And", a, b),
            U64SyntaxTree::Or(a, b) => binary_op_closure("Or", a, b),
            U64SyntaxTree::Nand(a, b) => binary_op_closure("Not And", a, b),
            U64SyntaxTree::Nor(a, b) => binary_op_closure("Not Or", a, b),
        }
    }

    /// Stringifies a `WhereSyntaxTree` for debugging purposes.
    #[allow(dead_code)]
    pub fn to_string(&self) -> String {
        self.to_string_lines(0).join("\n")
    }

    pub fn negate(self) -> Self {
        match self {
            U64SyntaxTree::True => U64SyntaxTree::False,
            U64SyntaxTree::False => U64SyntaxTree::True,
            U64SyntaxTree::Atom(a) => {
                let mut new_atom = a.clone();
                new_atom.negate();
                U64SyntaxTree::Atom(new_atom)
            }
            U64SyntaxTree::And(a, b) => U64SyntaxTree::Nand(a, b),
            U64SyntaxTree::Nand(a, b) => U64SyntaxTree::And(a, b),
            U64SyntaxTree::Or(a, b) => U64SyntaxTree::Nor(a, b),
            U64SyntaxTree::Nor(a, b) => U64SyntaxTree::Or(a, b),
        }
    }

    fn string_to_u64_list(s: String) -> Vec<u64> {
        let s_len = s.len();
        let s_bytes = s.as_bytes();
        let mut result: Vec<u64> = Vec::new();

        let get_or_zero = |j: usize| (if j < s_len { s_bytes[j] } else { 0u8 }) as u64;

        for i in 0..4 {
            let j = 8 * i;
            let b = [
                get_or_zero(j),
                get_or_zero(j + 1),
                get_or_zero(j + 2),
                get_or_zero(j + 3),
                get_or_zero(j + 4),
                get_or_zero(j + 5),
                get_or_zero(j + 6),
                get_or_zero(j + 7),
            ];
            let u64_from_bytes = (b[0] << 56)
                + (b[1] << 48)
                + (b[2] << 40)
                + (b[3] << 32)
                + (b[4] << 24)
                + (b[5] << 16)
                + (b[6] << 8)
                + (b[7]);
            result.push(u64_from_bytes);
        }
        result
    }

    fn from_string(index: u8, op: ComparisonOp, s: String) -> Self {
        let values = Self::string_to_u64_list(s);
        let mut result = Self::Atom(U64Atom {
            index,
            op: ComparisonOp::Equal, // NotEqual is handled at the end
            value: values[0],
        });

        for i in 1..4 {
            let right_child = Self::Atom(U64Atom {
                index: index + i,
                op: ComparisonOp::Equal,
                value: values[i as usize],
            });
            result = Self::And(Box::new(result), Box::new(right_child));
        }

        match op {
            ComparisonOp::NotEqual => result.negate(),
            _ => result,
        }
    }

    /// Creates a `U64SyntaxTree` from a term of type `(Ident, BinaryOperator, Value)`.
    pub fn from_value(
        sqlparser_term: (Ident, BinaryOperator, Value),
        headers: &TableHeaders,
    ) -> Self {
        let ident = sqlparser_term.0.value;
        let cell_type = headers.type_of(ident.clone()).unwrap();
        let index = headers.index_of(ident.clone()).unwrap();

        let parse_u8 = |s: String| u8::from_str(s.as_str()).unwrap() as u64;
        let parse_u16 = |s: String| u16::from_str(s.as_str()).unwrap() as u64;
        let parse_u32 = |s: String| u32::from_str(s.as_str()).unwrap() as u64;

        // switch the MSB of signed integers so that
        // parse_i8(-1) < parse_i8(1)
        let parse_i8 = |s: String| (i8::from_str(s.as_str()).unwrap() as u64) ^ (1 << 63);
        let parse_i16 = |s: String| (i16::from_str(s.as_str()).unwrap() as u64) ^ (1 << 63);
        let parse_i32 = |s: String| (i32::from_str(s.as_str()).unwrap() as u64) ^ (1 << 63);
        let parse_i64 = |s: String| (i64::from_str(s.as_str()).unwrap() as u64) ^ (1 << 63);

        let op = ComparisonOp::from(sqlparser_term.1);

        let build_self = |u: u64| {
            Self::Atom(U64Atom {
                index,
                op: op.clone(),
                value: u,
            })
        };

        match (cell_type, sqlparser_term.2) {
            (CellType::Bool, Value::Boolean(b)) => build_self(b as u64),
            (CellType::U8, Value::Number(n, _b)) => build_self(parse::<u8>(n)),
            (CellType::U16, Value::Number(n, _b)) => build_self(parse::<u16>(n)),
            (CellType::U32, Value::Number(n, _b)) => build_self(parse::<u32>(n)),
            (CellType::U64, Value::Number(n, _b)) => build_self(parse::<u64>(n)),
            (CellType::I8, Value::Number(n, _b)) => build_self(parse_signed::<i8>(n)),
            (CellType::I16, Value::Number(n, _b)) => build_self(parse_signed::<i16>(n)),
            (CellType::I32, Value::Number(n, _b)) => build_self(parse_signed::<i32>(n)),
            (CellType::I64, Value::Number(n, _b)) => build_self(parse_signed::<i64>(n)),
            (CellType::ShortString, Value::UnQuotedString(s))
            | (CellType::ShortString, Value::SingleQuotedString(s)) => {
                Self::from_string(index, op, s)
            }
            (c, t) => panic!("Type error: {ident} has type {c:?}, got {t:?}",),
        }
    }

    /// Builds a `U64SyntaxTree` from a term of the form `ident1 op ident2`.
    pub fn from_ident(
        sqlparser_term: (Ident, BinaryOperator, Ident),
        headers: &TableHeaders,
    ) -> Self {
        let index = headers.index_of(sqlparser_term.0.to_string()).unwrap();
        let op = ComparisonOp::from(sqlparser_term.1);
        let value = sqlparser_term.2.value;
        Self::from_string(index, op, value)
    }

    /// Returns its index in the `Vec<EncodedInstruction>` after calling
    /// `Self::encode`.
    ///
    /// A node is encoded after its children, so that `self.index(base_index) =
    /// base_index + (size of the subtree rooted at self)`
    fn index(&self, base_index: u8) -> u8 {
        match self {
            Self::Atom(_) | Self::True | Self::False => base_index,
            Self::And(a, b) | Self::Nand(a, b) | Self::Or(a, b) | Self::Nor(a, b) => {
                b.index(a.index(base_index) + 1) + 1
            }
        }
    }

    /// Encodes itself into a `Vec<EncodedInstruction64>`.
    pub fn encode_with_index(&self, base_index: u8) -> Vec<EncodedInstruction64> {
        let mut result: Vec<EncodedInstruction64> = Vec::new();

        let mut add_node = |a: &Box<Self>, b: &Box<Self>, which_op: bool, negate: bool| {
            result.append(&mut a.encode_with_index(base_index));
            let a_index = a.index(base_index);
            let b_index = b.index(a_index + 1);
            result.append(&mut b.encode_with_index(a_index + 1));
            result.push((true, a_index, which_op, (b_index as u64), negate));
        };
        match self {
            // HACK: False <=> query_lut.get(current_index) != 0
            Self::False => result.push((false, base_index, false, 0u64, true)),
            // HACK: True <=> no instruction
            Self::True => (),
            Self::Atom(a) => result.push(a.encode()),
            Self::And(a, b) => add_node(a, b, false, false),
            Self::Nand(a, b) => add_node(a, b, false, true),
            Self::Or(a, b) => add_node(a, b, true, false),
            Self::Nor(a, b) => add_node(a, b, true, true),
        }
        result
    }

    /// Encodes itself into a `Vec<EncodedInstruction64>`.
    pub fn encode(&self) -> Vec<EncodedInstruction64> {
        self.encode_with_index(0_u8)
    }

    /// Encrypts a `WhereSyntaxTree`.
    ///
    /// First applies `Self::simplify()` from module `simplify_query`, then
    /// encodes itself, and encrypts each element of the resulting vector.
    pub fn encrypt(&self, client_key: &ClientKey) -> EncryptedSyntaxTree {
        self.simplify()
            .encode()
            .into_iter()
            .map(|(is_node, left, which_op, right, negate)| {
                (
                    client_key.encrypt_one_block(is_node as u64),
                    client_key.encrypt_radix(left as u64, 4),
                    client_key.encrypt_one_block(which_op as u64),
                    client_key.encrypt_radix(right as u64, 32),
                    client_key.encrypt_one_block(negate as u64),
                )
            })
            .collect()
    }
}

impl From<(Expr, &TableHeaders)> for U64SyntaxTree {
    fn from((expr, headers): (Expr, &TableHeaders)) -> Self {
        match expr {
            Expr::Nested(e) => Self::from((e.as_ref().to_owned(), headers)),
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr: e,
            } => Self::from((e.as_ref().to_owned(), headers)).negate(),
            Expr::UnaryOp { op, .. } => panic!("unknown unary operator {op:?}"),
            Expr::BinaryOp {
                ref left,
                ref op,
                ref right,
            } => match (left.as_ref().to_owned(), right.as_ref().to_owned()) {
                // builds an Atom from a SQL expression `column OP value`
                (Expr::Identifier(i_left), Expr::Value(v_right)) => {
                    Self::from_value((i_left, op.to_owned(), v_right), headers)
                }
                (Expr::Identifier(i_left), Expr::Identifier(i_right))
                    if op == &BinaryOperator::Eq || op == &BinaryOperator::NotEq =>
                {
                    Self::from_ident((i_left, op.to_owned(), i_right), headers)
                }
                // recursively builds a syntax tree from a SQL expression `l OP
                // r` where OP is one of AND, OR, and l, r are SQL expressions
                (l, r) => {
                    let left = Self::from((l.clone(), headers));
                    let right = Self::from((r.clone(), headers));
                    match op {
                        BinaryOperator::And => Self::And(Box::new(left), Box::new(right)),
                        BinaryOperator::Or => Self::Or(Box::new(left), Box::new(right)),
                        _ => panic!("unknown expression: {l} {op} {r}"),
                    }
                }
            },
            _ => todo!(),
        }
    }
}

pub fn parse_query(path: PathBuf) -> Statement {
    let dialect = GenericDialect {};
    let str_query = read_to_string(path.clone()).expect(
        format!(
            "Could not load query file at {}",
            path.to_str().expect("invalid Unicode for {path:?}")
        )
        .as_str(),
    );
    let ast = Parser::parse_sql(&dialect, &str_query).unwrap();
    ast[0].clone()
}

pub fn build_u64_syntax_tree(statement: Statement, headers: &TableHeaders) -> U64SyntaxTree {
    match statement {
        Statement::Query(q) => match q.body.as_ref() {
            SetExpr::Select(s) => U64SyntaxTree::from((s.selection.clone().unwrap(), headers)),
            _ => panic!("unknown query: {q:?}"),
        },
        _ => panic!("unknown statement: {statement:?}"),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    // #[test]
    // fn print_query() {
    //     let query_path = PathBuf::from("query.txt");
    //     let query = build_where_syntax_tree(parse_query(query_path));

    //     println!("query: \n{}\n", query.to_string());
    // }

    // #[test]
    // pub fn encode_short_string() {
    //     let dialect = GenericDialect {};
    //     let str_query = "SELECT * from table_1 WHERE some_str=\"first_line\"";
    //     let ast = Parser::parse_sql(&dialect, &str_query).unwrap();
    //     let query = build_where_syntax_tree(ast[0].clone());
    //     let headers = TableHeaders(vec![
    //         ("some_int".to_string(), CellType::U32),
    //         ("some_bool".to_string(), CellType::Bool),
    //         ("some_str".to_string(), CellType::ShortString),
    //     ]);
    //     let encoded_query = query.encode(&headers);
    //     if let WhereSyntaxTree::Atom(a) = query {
    //         println!("encoded short string: {:?}", a.value.encode());
    //     }
    //     encoded_query.iter().for_each(|a| println!("{a:?}"));
    // }
}
