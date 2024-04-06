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
    next_index: u8,
    node: Node,
}

/// Holds a tuple `(is_op, left, which_op, right, negate)`. Each tuple represents
/// either one `WhereSyntaxTree::Atom` (unless the value type is `ShortString`) or
/// one `WhereSyntaxTree::Node`. Each `Atom` value is encoded as one `u32`, except
/// `ShortString` which is encoded as a eight `u32`s.
///
/// The encoding is made as follows:
/// - `is_op`:
///   - `true`: the tuple encodes a binary `Node`
///     1. `left`: index of the left child,
///     2. `which_op`:
///         - `true`: `AND`,
///         - `false`: `OR`,
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

/// Encrypted variant of `EncodedInstruction`.
///
/// Holds a tuple `(is_op, left, which_op, right, negate)`, where:
/// - `is_op` is an encrypted boolean,
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

impl AtomicCondition {
    /// Extracts the type of a cell appearing in an `AtomicCondition`.
    fn cell_type(&self) -> CellType {
        CellType::from(&self.value)
    }

    /// Creates a `String` representation of an atom for debugging purposes.
    fn to_string(&self) -> String {
        format!(
            "{} {} {}",
            self.ident.to_string(),
            self.op.to_string(),
            self.value.to_string()
        )
    }

    /// Encodes an `AtomicCondition` into a (vector of) [`EncodedInstruction`]s.
    /// See there for how an atomic condition is encoded.
    pub fn encode(
        &self,
        headers: &TableHeaders,
        base_atom_index: u8,
        negate: bool,
    ) -> Vec<EncodedInstruction> {
        // an encoded cell value is either one u32 or eight u32
        // - in the first case one encoded atom is produced
        // - in the second case, eight atoms are produced, plus the seven atoms
        //   corresponding to the ANDs.
        let encoded_len = 2 * self.cell_type().len() - 1;

        let mut result = Vec::<EncodedInstruction>::with_capacity(encoded_len);
        let base_index = headers.index_of(self.ident.clone()).unwrap();
        let base_atom_index = base_atom_index as usize;

        match self.cell_type() {
            CellType::ShortString => {
                let inner_negate = match &self.op {
                    ComparisonOp::Equal => false,
                    ComparisonOp::NotEqual => true,
                    o => panic!("Operator {o:?} unsupported for String."),
                };

                let is_negated = negate ^ inner_negate;

                // encode each atom
                for (i, v_i) in self.value.encode().into_iter().enumerate() {
                    result.push((
                        false,                  // encrypt an atom
                        (base_index + i) as u8, // encrypt the column id
                        false,                  // encrypt the `=` operator
                        v_i,                    // encrypt the value to the right of `=`
                        is_negated,             // negate if self.op is `NotEqual`
                    ));
                }

                // encode the conjunction result[0] AND result[1] ... AND result[7]
                let content_len = self.cell_type().len();
                let ops_index = base_atom_index + content_len;

                // result[0] AND result[1]
                result.push((
                    true,
                    base_atom_index as u8,
                    true,
                    (base_atom_index + 1) as u32,
                    false,
                ));

                // result[something + i] = result[i] AND result[something + i - 1]
                for i in 2..content_len {
                    result.push((
                        true,
                        (base_atom_index + i) as u8,
                        true,
                        (ops_index + i - 2) as u32,
                        false,
                    ))
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
                    false,                   // encrypt an atom
                    base_index as u8,        // the column index
                    op,                      // the operator
                    val,                     // the value
                    (negate ^ inner_negate), // negate the result ?
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn to_string(&self) -> String {
        self.to_string_lines().join("\n")
    }

    /// Encodes a `WhereSyntaxTree` as a vector of `EncodedInstruction`s.
    pub fn encode(&self, headers: &TableHeaders, negate: bool) -> Vec<EncodedInstruction> {
        match &self.node {
            Node::Atom(a) => a.encode(headers, self.index, negate),
            Node::And(a, b) => {
                let mut result = a.encode(headers, false);
                result.append(&mut b.encode(headers, false));
                result.push((
                    true,           // encode operator
                    a.index,        // encode left index
                    true,           // encode AND
                    b.index as u32, // encode right index
                    negate,         // encode negate
                ));
                result
            }
            Node::Or(a, b) => {
                let mut result = a.encode(headers, false);
                result.append(&mut b.encode(headers, false));
                result.push((
                    true,           // encode operator
                    a.index,        // encode left index
                    false,          // encode OR
                    b.index as u32, // encode right index
                    negate,         // encode negate
                ));
                result
            }
            Node::Not(node) => node.encode(headers, !negate),
        }
    }

    /// Encrypts a `WhereSyntaxTree`.
    ///
    /// First encodes itself, then encrypt each element of the resulting vector.
    pub fn encrypt(
        &self,
        client_key: &ClientKey,
        headers: &TableHeaders,
        negate: bool,
    ) -> EncryptedSyntaxTree {
        self.encode(headers, negate)
            .into_iter()
            .map(|(is_op, left, which_op, right, negate)| {
                (
                    client_key.encrypt_one_block(is_op as u64),
                    client_key.encrypt_radix(left as u64, 4),
                    client_key.encrypt_one_block(which_op as u64),
                    client_key.encrypt_radix(right as u64, 16),
                    client_key.encrypt_one_block(negate as u64),
                )
            })
            .collect()
    }
}

/// Builds an `WhereSyntaxTree` from a `base_index: u8` and a `sqlparser::Expr`.
/// This is used to discard all unnecessary data that comes along a
/// `sqlparser::Expr`.
///
/// The argument `base_index` is used when encoding the `WhereSyntaxTree`. See at
/// [`EncodedInstruction`] for more explanation.
impl From<(u8, Expr)> for WhereSyntaxTree {
    fn from((base_index, expr): (u8, Expr)) -> Self {
        match expr {
            Expr::Nested(e) => Self::from((base_index, e.as_ref().to_owned())),
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr: e,
            } => {
                let child = Self::from((base_index, e.as_ref().to_owned()));
                let index = child.index; // Not gates are simplified during encryption
                Self {
                    index,
                    next_index: child.next_index,
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
                (Expr::Identifier(i_left), Expr::Value(v_right)) => {
                    let atom = AtomicCondition::from((i_left, op.to_owned(), v_right));
                    let next_index = base_index + atom.cell_type().len() as u8;
                    Self {
                        index: base_index,
                        next_index,
                        node: Node::Atom(atom),
                    }
                }
                (Expr::Identifier(i_left), Expr::Identifier(i_right))
                    if op == &BinaryOperator::Eq || op == &BinaryOperator::NotEq =>
                {
                    let atom = AtomicCondition::from((i_left, op.to_owned(), i_right));
                    let next_index = base_index + atom.cell_type().len() as u8;
                    Self {
                        index: base_index,
                        next_index,
                        node: Node::Atom(atom),
                    }
                }
                // recursively builds a syntax tree from a SQL expression `l OP r`
                // where OP is one of AND, OR
                // and l, r are SQL expressions
                (l, r) => {
                    let left = Self::from((base_index, l.clone()));
                    let right = Self::from((left.next_index, r.clone()));
                    let index = right.next_index;
                    match op {
                        BinaryOperator::And => Self {
                            index,
                            next_index: index + 1,
                            node: Node::And(Box::new(left), Box::new(right)),
                        },
                        BinaryOperator::Or => Self {
                            index,
                            next_index: index + 1,
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
