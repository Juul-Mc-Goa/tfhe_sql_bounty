//! Query parsing and manipulation.
//!
//! This module contains types for an internal representation of queries, as
//! well as methods for encoding and encrypting them.

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

#[derive(Clone, Debug)]
pub enum Node {
    Atom(AtomicCondition),
    Not(Box<WhereSyntaxTree>),
    And(Box<WhereSyntaxTree>, Box<WhereSyntaxTree>),
    Or(Box<WhereSyntaxTree>, Box<WhereSyntaxTree>),
}

/// A simple enum holding the syntax tree to the right of the `WHERE` keyword.
///
/// The field `index` is used during encryption: an encrypted `WhereSyntaxTree` is
/// a vector of `EncryptedInstruction` (each of which encrypts a `Node`), `index` holds
/// the location of the encrypted `Node` in that vector.
#[derive(Clone, Debug)]
pub struct WhereSyntaxTree {
    index: u8,
    node: Node,
}

/// Holds a tuple `(is_op, left, which_op, right, negate)`, where:
/// - `is_op` is an encrypted boolean,
/// - `left` is an encrypted u8,
/// - `which_op` is an encrypted boolean,
/// - `right` is an encrypted u32,
/// - `negate` is an encrypted boolean.
///
/// The first element `is_op` of the tuple encodes wether the rest of the tuple
/// is to be understood as an atom or a boolean operator:
/// - `is_op`:
///   - `true`: the tuple encodes a boolean operator
///     - `left`: the (encrypted) index of the left child,
///     - `which_op`:
///       - `true`: `AND`,
///       - `false`: `OR`,
///     - `right`: the (encrypted) index of the right child,
///   - `false`: the tuple encodes an atom
///     - `left`: the (encrypted) column identifier,
///     - `which_op`:
///       - `true`: `<=`,
///       - `false`: `=`,
///     - `right`: the value against which left is tested,
/// - `negate`: encodes wether to negate the boolean result of `left which_op
///    right`.
pub type EncryptedInstruction = (
    Ciphertext,
    RadixCiphertext,
    Ciphertext,
    RadixCiphertext,
    Ciphertext,
);

/// A type alias for storing (the encryption of) a `WHERE` syntax tree.
///
/// It is a vector of `(CipherText, RadixCipherText, CipherText, RadixCiphertext, CipherText)`,
/// where each tuple represents either an `Atom` or a boolean operator (`AND`, `OR`).
///
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

impl AtomicCondition {
    /// Extracts the type of a cell (int, unsigned int, or short string).
    fn cell_type(&self) -> CellType {
        CellType::from(&self.value)
    }
    /// Negates an `AtomicCondition`.
    fn negate(&self) -> Self {
        let (ident, value) = (self.ident.clone(), self.value.clone());
        let op = match self.op {
            ComparisonOp::Equal => ComparisonOp::NotEqual,
            ComparisonOp::NotEqual => ComparisonOp::Equal,
            ComparisonOp::LessEqual => ComparisonOp::GreaterThan,
            ComparisonOp::GreaterThan => ComparisonOp::LessEqual,
            ComparisonOp::LessThan => ComparisonOp::GreaterEqual,
            ComparisonOp::GreaterEqual => ComparisonOp::LessThan,
        };
        AtomicCondition { ident, op, value }
    }
    fn to_string(&self) -> String {
        format!(
            "{} {} {}",
            self.ident.to_string(),
            self.op.to_string(),
            self.value.to_string()
        )
    }

    /// Encrypts itself into an `Vec<EncryptedInstruction>`.
    ///
    /// # Inputs:
    /// - `client_key` is used for encryption,
    /// - `headers` is used to get an `u8` from a column identifier.
    /// # Outputs:
    /// a vector of `EncryptedInstruction`, each element being:
    /// - at index 0: an encryption of `false`,
    /// - at index 1: the encrypted u8 identifying a column,
    /// - at index 2: an encrypted `bool` for choosing an operator. If `true` then use `<=`,
    ///     otherwise use `=`,
    /// - at index 3: the encrypted value against which the column is tested,
    /// - at index 4: an encrypted `bool` for negating the boolean result of `column OP value`.
    pub fn encrypt(
        &self,
        client_key: &ClientKey,
        headers: &TableHeaders,
        negate: bool,
    ) -> Vec<EncryptedInstruction> {
        let mut result = Vec::<EncryptedInstruction>::with_capacity(self.cell_type().len());
        let base_index = headers.index_of(self.ident.clone()).unwrap();

        match self.cell_type() {
            CellType::ShortString => {
                let is_negated = match &self.op {
                    ComparisonOp::Equal => false,
                    ComparisonOp::NotEqual => true,
                    o => panic!("Operator {o:?} unsupported for String."),
                };
                for (i, ct_i) in self.value.encrypt(&client_key).into_iter().enumerate() {
                    result.push((
                        client_key.encrypt_bool(false).into_inner(), // encrypt an atom
                        client_key.encrypt_radix(base_index + (i as u8), 4), // encrypt the column id
                        client_key.encrypt_bool(false).into_inner(), // encrypt the `=` operator
                        ct_i, // encrypt the value to the right of `=`
                        client_key.encrypt_one_block(is_negated as u64), // negate if self.op is `NotEqual`
                    ));
                }
            }
            _ => {
                // every other type is encoded as one u32
                let u32_value = self.value.encode()[0];
                let (op, inner_negate, val) = match self.op {
                    ComparisonOp::Equal => (false, false, u32_value),
                    ComparisonOp::NotEqual => (false, true, u32_value),
                    ComparisonOp::LessEqual => (true, false, u32_value),
                    ComparisonOp::GreaterThan => (true, true, u32_value), // a > b <=> not(a <= b)
                    ComparisonOp::LessThan => (true, false, u32_value - 1), // a < b <=> a <= b-1
                    ComparisonOp::GreaterEqual => (true, true, u32_value - 1), // a >= b <=> not(a <= b-1)
                };
                result.push((
                    client_key.encrypt_bool(false).into_inner(), // encrypt an atom
                    client_key.encrypt_radix(base_index, 4),     // encrypt the column id
                    client_key.encrypt_one_block(op as u64),
                    client_key.encrypt_radix(val, 16),
                    client_key.encrypt_one_block((negate ^ inner_negate) as u64),
                ));
            }
        }
        result
    }
}

/// Creates an `AtomicCondition` from a tuple `(identifier, operator, value)`, where `value`
/// is either a boolean or an integer.
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

/// Creates an `AtomicCondition` from a tuple `(identifier, operator, value)`, where `value`
/// is a String.
impl From<(Ident, BinaryOperator, Ident)> for AtomicCondition {
    fn from(sqlparser_term: (Ident, BinaryOperator, Ident)) -> Self {
        let ident = sqlparser_term.0.value;
        let op = ComparisonOp::from(sqlparser_term.1);
        let value = CellContent::ShortString(sqlparser_term.2.value);
        Self { ident, op, value }
    }
}

impl WhereSyntaxTree {
    /// Stringifies a `WhereSyntaxTree` for debugging purposes.
    fn to_string_lines(&self) -> Vec<String> {
        let indent_closure =
            |v: Vec<String>| v.iter().map(|s| format!("  {s}")).collect::<Vec<String>>();
        let binary_op_closure = |op: &str, a: &Box<WhereSyntaxTree>, b: &Box<WhereSyntaxTree>| {
            let mut result = vec![format!("({}) {op}", self.index)];
            let mut left: Vec<String> = indent_closure(a.to_string_lines());
            let mut right: Vec<String> = indent_closure(b.to_string_lines());
            result.append(&mut left);
            result.append(&mut right);
            result
        };
        match &self.node {
            Node::Atom(a) => vec![format!("({}) {}", self.index, a.to_string())],
            Node::And(a, b) => binary_op_closure("And", a, b),
            Node::Or(a, b) => binary_op_closure("Or", a, b),
            Node::Not(a) => {
                let mut result = a.to_string_lines();
                result[0] = format!("({}) Not {}", self.index, &result[0]);
                result
            }
        }
    }

    /// Stringifies a `WhereSyntaxTree` for debugging purposes.
    pub fn to_string(&self) -> String {
        self.to_string_lines().join("\n")
    }

    /// Encrypts the syntax tree as a vector of elements `(encrypted_atom, op)` where
    /// `op` is a boolean:
    /// - `op == true`: apply `AND` operator,
    /// - `op == false`: apply `OR` operator.
    /// The final element's `op` is ignored.
    ///
    /// <div class="warning">This method assumes that the syntax tree is in disjunctive normal form.</div>
    pub fn encrypt(
        &self,
        client_key: &ClientKey,
        headers: &TableHeaders,
        negate: bool,
    ) -> EncryptedSyntaxTree {
        match &self.node {
            Node::Atom(a) => a.encrypt(client_key, headers, negate),
            Node::And(a, b) => {
                let mut result = a.encrypt(client_key, headers, false);
                result.append(&mut b.encrypt(client_key, headers, false));
                result.push((
                    client_key.encrypt_bool(true).into_inner(), // encrypt operator
                    client_key.encrypt_radix(a.index, 4),       // encrypt left index
                    client_key.encrypt_bool(true).into_inner(), // encrypt AND
                    client_key.encrypt_radix(b.index, 16),      // encrypt right index
                    client_key.encrypt_bool(negate).into_inner(), // encrypt negate
                ));
                result
            }
            Node::Or(a, b) => {
                let mut result = a.encrypt(client_key, headers, false);
                result.append(&mut b.encrypt(client_key, headers, false));
                result.push((
                    client_key.encrypt_bool(true).into_inner(), // encrypt operator
                    client_key.encrypt_radix(a.index, 4),       // encrypt left index
                    client_key.encrypt_bool(false).into_inner(), // encrypt OR
                    client_key.encrypt_radix(b.index, 16),      // encrypt right index
                    client_key.encrypt_bool(negate).into_inner(), // encrypt negate
                ));
                result
            }
            Node::Not(_) => panic!("Encountered a NOT operator during encryption."),
        }
    }
}

/// Builds an `WhereSyntaxTree` from a `sqlparser::Expr`. This is used to discard all
/// unnecessary data that comes along a `sqlparser::Expr`.
impl From<(u8, Expr)> for WhereSyntaxTree {
    fn from((parent_id, expr): (u8, Expr)) -> Self {
        match expr {
            Expr::Nested(e) => Self::from((parent_id, e.as_ref().to_owned())),
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr: e,
            } => {
                let child = Self::from((parent_id, e.as_ref().to_owned()));
                let index = child.index; // Not gates are simplified during encryption
                Self {
                    index,
                    node: Node::Not(Box::new(child)),
                }
            }
            Expr::UnaryOp { op, .. } => panic!("unknown unary operator {op:?}"),
            Expr::BinaryOp {
                ref left,
                ref op,
                ref right,
            } => match (left.as_ref().to_owned(), right.as_ref().to_owned()) {
                // builds an Atom from a SQL expression `column OP value`
                (Expr::Identifier(i_left), Expr::Value(v_right)) => Self {
                    index: parent_id,
                    node: Node::Atom(AtomicCondition::from((i_left, op.to_owned(), v_right))),
                },
                (Expr::Identifier(i_left), Expr::Identifier(i_right))
                    if op == &BinaryOperator::Eq =>
                {
                    Self {
                        index: parent_id,
                        node: Node::Atom(AtomicCondition::from((i_left, op.to_owned(), i_right))),
                    }
                }
                // recursively builds a syntax tree from a SQL expression `l OP r`
                // where OP is one of AND, OR
                // and l, r are SQL expressions
                (l, r) => {
                    let left = Self::from((parent_id, l.clone()));
                    let right = Self::from((left.index + 1, r.clone()));
                    let index = right.index + 1;
                    match op {
                        BinaryOperator::And => Self {
                            index,
                            node: Node::And(Box::new(left), Box::new(right)),
                        },
                        BinaryOperator::Or => Self {
                            index,
                            node: Node::Or(Box::new(left), Box::new(right)),
                        },
                        _ => panic!("unknown expression: {l} {op} {r}"),
                    }
                }
            },
            _ => todo!(),
        }
    }
}

/// Builds an `WhereSyntaxTree` from a `sqlparser::Expr`. This is used to discard all
/// unnecessary data that comes along a `sqlparser::Expr`.
impl From<Expr> for WhereSyntaxTree {
    fn from(e: Expr) -> Self {
        Self::from((0, e))
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

pub fn build_where_syntax_tree(statement: Statement) -> WhereSyntaxTree {
    match statement {
        Statement::Query(q) => match q.body.as_ref() {
            SetExpr::Select(s) => WhereSyntaxTree::from(s.selection.clone().unwrap()),
            _ => panic!("unknown query: {q:?}"),
        },
        _ => panic!("unknown statement: {statement:?}"),
    }
}

mod tests {
    use super::*;

    fn print_query() {
        let query_path = PathBuf::from("query.txt");
        let query = build_where_syntax_tree(parse_query(query_path));

        println!("query: \n{}\n", query.to_string());
    }
}
