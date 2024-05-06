//! Query parsing and manipulation.
//!
//! This module contains types for an internal representation of queries, as
//! well as methods for encoding and encrypting them.

use crate::cipher_structs::FheBool;
use crate::{encoding::*, DatabaseHeaders};
use crate::{CellType, TableHeaders};

use sqlparser::ast::{
    BinaryOperator, Expr, Ident, SelectItem, SetExpr, Statement, TableFactor, UnaryOperator, Value,
};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

use std::{fs::read_to_string, path::PathBuf};

use tfhe::integer::{ClientKey, RadixCiphertext};
use tfhe::shortint::{Ciphertext, ServerKey};

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

/// An atomic condition of the form `column OP value` where `value` is of type
/// `u64`.
#[derive(Clone, Debug)]
pub struct U64Atom {
    pub index: u8,
    pub op: ComparisonOp,
    pub value: u64,
}

/// A simple enum holding the syntax tree to the right of the `WHERE` keyword.
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

/// A query of the form:
/// ```
/// SELECT <DISTINCT?> <column_selection> FROM <table_selection> WHERE
/// <where_condition>
/// ```
#[derive(Clone, Debug)]
pub struct ClearQuery {
    pub distinct: bool,
    pub projection: Vec<bool>,
    pub sql_projection: Vec<sqlparser::ast::SelectItem>,
    pub table_selection: u8,
    pub where_condition: U64SyntaxTree,
}

/// Holds a tuple `(is_node, left, which_op, right, negate)`. Each tuple represents
/// either one `U64SyntaxTree::Atom` (unless the value type is `ShortString`) or
/// one ndoe. Each `Atom` value is encoded as one `u64`, except
/// `ShortString` which is encoded as a four `u64`s.
///
/// The encoding is made as follows:
/// - `is_node`:
///   - `true`: the tuple encodes a boolean node
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
pub type EncodedInstruction = (bool, u8, bool, u64, bool);

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

/// An encrypted query of the form:
/// ```
/// SELECT <DISTINCT?> <column_selection> FROM <table_selection> WHERE
/// <where_condition>
/// ```
pub struct EncryptedQuery<'a> {
    /// An encrypted boolean
    pub distinct: FheBool<'a>,
    /// A list of encrypted column indices
    pub projection: Vec<FheBool<'a>>,
    /// The encrypted index of the table
    pub table_selection: RadixCiphertext,
    /// An encrypted where condition
    pub where_condition: EncryptedSyntaxTree,
}

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
    #[allow(clippy::inherent_to_string)]
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
    #[allow(clippy::inherent_to_string)]
    fn to_string(&self) -> String {
        format!("id_{} {} {}", self.index, self.op.to_string(), self.value)
    }

    pub fn encode(&self) -> EncodedInstruction {
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
        let binary_op_closure = |op: &str, a: &U64SyntaxTree, b: &U64SyntaxTree| {
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

    /// Stringifies a `U64SyntaxTree` for debugging purposes.
    #[allow(dead_code)]
    #[allow(clippy::inherent_to_string)]
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

    pub fn do_negation(self, negate: bool) -> Self {
        if negate {
            self.negate()
        } else {
            self
        }
    }

    fn from_string(index: u8, op: ComparisonOp, s: String) -> Self {
        let values = encode_string(s);
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
            | (CellType::ShortString, Value::SingleQuotedString(s))
            | (CellType::ShortString, Value::DoubleQuotedString(s))
            | (CellType::ShortString, Value::EscapedStringLiteral(s))
            | (CellType::ShortString, Value::SingleQuotedByteStringLiteral(s))
            | (CellType::ShortString, Value::DoubleQuotedByteStringLiteral(s))
            | (CellType::ShortString, Value::RawStringLiteral(s)) => {
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
    pub fn encode_with_index(&self, base_index: u8) -> Vec<EncodedInstruction> {
        let mut result: Vec<EncodedInstruction> = Vec::new();

        let mut add_node = |a: &Self, b: &Self, which_op: bool, negate: bool| {
            result.append(&mut a.encode_with_index(base_index));
            let a_index = a.index(base_index);
            let b_index = b.index(a_index + 1);
            result.append(&mut b.encode_with_index(a_index + 1));
            result.push((true, a_index, which_op, (b_index as u64), negate));
        };
        match self {
            // HACK: False <=> query_lut.get(current_index) AND query_lut.get(current_index) == true
            Self::False => result.push((true, base_index, false, base_index as u64, false)),
            Self::True => (), // True <=> no instruction
            Self::Atom(a) => result.push(a.encode()),
            Self::And(a, b) => add_node(a, b, false, false),
            Self::Nand(a, b) => add_node(a, b, false, true),
            Self::Or(a, b) => add_node(a, b, true, false),
            Self::Nor(a, b) => add_node(a, b, true, true),
        }
        result
    }

    /// Encodes itself into a `Vec<EncodedInstruction64>`.
    pub fn encode(&self) -> Vec<EncodedInstruction> {
        self.encode_with_index(0_u8)
    }

    /// Encrypts a `U64SyntaxTree`.
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
                    client_key.encrypt_radix(right, 32),
                    client_key.encrypt_one_block(negate as u64),
                )
            })
            .collect()
    }
}

/// Parses a `sqlparser::ast::Expr` into a `U64SyntaxTree`, using a
/// `&TableHeaders` for converting column identifiers to `u8` indices.
impl From<(Expr, &TableHeaders)> for U64SyntaxTree {
    fn from((expr, headers): (Expr, &TableHeaders)) -> Self {
        match expr {
            Expr::Nested(e) => Self::from((e.as_ref().to_owned(), headers)),
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr: e,
            } => Self::from((e.as_ref().to_owned(), headers)).negate(),
            Expr::UnaryOp { op, .. } => panic!("unknown unary operator {op:?}"),
            Expr::InList {
                expr,
                list,
                negated,
            } => {
                let mut result = Self::False;
                for e in list {
                    let right_leg = Expr::BinaryOp {
                        left: expr.clone(),
                        op: BinaryOperator::Eq,
                        right: Box::new(e),
                    };
                    result = Self::Or(Box::new(result), Box::new(Self::from((right_leg, headers))));
                }
                result.do_negation(negated)
            }
            Expr::Between {
                expr,
                negated,
                low,
                high,
            } => {
                let left_leg = Expr::BinaryOp {
                    left: expr.clone(),
                    op: BinaryOperator::GtEq,
                    right: low,
                };
                let right_leg = Expr::BinaryOp {
                    left: expr,
                    op: BinaryOperator::LtEq,
                    right: high,
                };
                let result = Self::from((
                    Expr::BinaryOp {
                        left: Box::new(left_leg),
                        op: BinaryOperator::And,
                        right: Box::new(right_leg),
                    },
                    headers,
                ));
                result.do_negation(negated)
            }
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

impl ClearQuery {
    /// Encrypts each of its attributes to build an [`EncryptedQuery`].
    pub fn encrypt<'a>(
        &self,
        client_key: &'a ClientKey,
        server_key: &'a ServerKey,
    ) -> EncryptedQuery<'a> {
        let distinct = FheBool {
            ct: client_key.encrypt_one_block(self.distinct as u64),
            server_key,
        };
        let projection: Vec<_> = self
            .projection
            .iter()
            .map(|c| FheBool {
                ct: client_key.encrypt_one_block(*c as u64),
                server_key,
            })
            .collect();
        let table_selection = client_key.encrypt_radix(self.table_selection, 4);
        let where_condition = self.where_condition.encrypt(client_key);
        EncryptedQuery {
            distinct,
            projection,
            table_selection,
            where_condition,
        }
    }

    /// Pretty-printing
    pub fn pretty(&self) -> String {
        [
            "ClearQuery:".to_string(),
            format!("  distinct: {}", self.distinct),
            format!("  projection: {:?}", self.projection),
            format!("  table selection: {}", self.table_selection),
            "  where condition:".to_string(),
            self.where_condition.to_string(),
        ]
        .join("\n")
    }
}

/// Builds a [`ClearQuery`] from a `sqlparser::ast::Select`.
pub fn parse_query(query: sqlparser::ast::Select, headers: &DatabaseHeaders) -> ClearQuery {
    let distinct = query.distinct.is_some();

    let table_name = match &query.from[0].relation {
        TableFactor::Table { name, .. } => name.0[0].value.clone(),
        t => panic!("not a table name {t:?}"),
    };
    let table_selection = headers.table_index(table_name);

    let headers = headers.0[table_selection as usize].1.clone();

    let mut projection: Vec<bool> = vec![false; headers.len()];

    if query.projection.is_empty() {
        panic!("Query with empty selection");
    } else if let SelectItem::Wildcard(_) = query.projection[0] {
        projection.iter_mut().for_each(|p| {
            *p = true;
        });
    } else {
        for select_item in query.projection.clone() {
            match select_item {
                SelectItem::UnnamedExpr(Expr::Identifier(id)) => {
                    let ident = id.value.clone();
                    let index = headers
                        .index_of(ident.clone())
                        .expect("Column identifier {ident} does not exist");
                    let len = headers.type_of(ident).unwrap().len();

                    let (start, end) = (index as usize, (index as usize) + len);
                    projection[start..end].iter_mut().for_each(|p| {
                        *p = true;
                    });
                }
                _ => panic!("unknown selection: {select_item:?}"),
            }
        }
    }

    let where_condition = match query.selection {
        Some(selection) => U64SyntaxTree::from((selection.clone(), &headers)),
        None => U64SyntaxTree::True,
    };

    ClearQuery {
        distinct,
        projection,
        sql_projection: query.projection,
        table_selection,
        where_condition,
    }
}

/// Parses a query file specified by `path` into a `ClearQuery`.
///
/// # Inputs
/// + `path`:  a `PathBuf` to the file containing the SQL query,
/// + `headers`: a [`DatabaseHeaders`], ie a list of all table headers of a database.
///
/// # Output
/// A [`ClearQuery`].
pub fn parse_query_from_file(path: PathBuf, headers: &DatabaseHeaders) -> ClearQuery {
    let dialect = GenericDialect {};
    let str_query = read_to_string(path.clone()).unwrap_or_else(|_| {
        panic!(
            "Could not load query file at {}",
            path.to_str().expect("invalid Unicode for {path:?}")
        )
    });
    let ast = Parser::parse_sql(&dialect, &str_query).unwrap();
    let statement = ast[0].clone();
    match statement {
        Statement::Query(q) => match q.body.as_ref() {
            SetExpr::Select(s) => parse_query(s.as_ref().clone(), headers),
            _ => panic!("unknown query: {q:?}"),
        },
        _ => panic!("unknown statement: {statement:?}"),
    }
}
