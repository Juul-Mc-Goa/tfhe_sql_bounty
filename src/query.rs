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
pub struct U32Atom {
    pub index: u8,
    pub op: ComparisonOp,
    pub value: u32,
}

/// A variant of `WhereSyntaxTree` where `AtomicCondition` is replaced by `U32Atom`
#[derive(Clone, Debug)]
pub enum U32SyntaxTree {
    True,
    False,
    Atom(U32Atom),
    And(Box<U32SyntaxTree>, Box<U32SyntaxTree>),
    Or(Box<U32SyntaxTree>, Box<U32SyntaxTree>),
    Nand(Box<U32SyntaxTree>, Box<U32SyntaxTree>),
    Nor(Box<U32SyntaxTree>, Box<U32SyntaxTree>),
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

impl U32Atom {
    pub fn negate(&mut self) {
        self.op.negate()
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

    pub fn negate(&mut self) {
        self.op.negate()
    }

    pub fn to_u32_syntax_tree(&self, headers: &TableHeaders) -> U32SyntaxTree {
        let base_index = headers.index_of(self.ident.clone()).unwrap() as u8;
        match self.cell_type() {
            CellType::ShortString => {
                let u32_vec = self.value.encode();
                let mut result = U32SyntaxTree::Atom(U32Atom {
                    index: base_index,
                    op: ComparisonOp::Equal,
                    value: u32_vec[0],
                });
                for (v, i) in u32_vec[1..].iter().zip(1..) {
                    result = U32SyntaxTree::And(
                        Box::new(result),
                        Box::new(U32SyntaxTree::Atom(U32Atom {
                            index: base_index + (i as u8),
                            op: ComparisonOp::Equal,
                            value: *v,
                        })),
                    );
                }
                match &self.op {
                    ComparisonOp::Equal => result,
                    ComparisonOp::NotEqual => result.negate(),
                    o => panic!("Operator {o:?} unsupported for String."),
                }
            }
            _ => U32SyntaxTree::Atom(U32Atom {
                index: base_index,
                op: self.op.clone(),
                value: self.value.encode()[0],
            }),
        }
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
                        false,                  // encode an atom
                        (base_index + i) as u8, // encode the column id
                        false,                  // encode the `=` operator
                        v_i,                    // encode the value to the right of `=`
                        false,                  // negation is handled afterward
                    ));
                }

                // encode the conjunction result[0] AND result[1] ... AND result[7]
                let content_len = self.cell_type().len();
                let ops_index = base_atom_index + content_len;

                // result[0] AND result[1]
                result.push((
                    true,
                    base_atom_index as u8,
                    false,
                    (base_atom_index + 1) as u32,
                    false,
                ));

                // result[i+8] = result[i] AND result[i + 7]
                for i in 2..content_len {
                    result.push((
                        true,
                        (base_atom_index + i) as u8,
                        false,
                        (ops_index + i - 2) as u32,
                        false,
                    ))
                }

                // handles negation
                let root_and_gate = result.last_mut().unwrap();
                root_and_gate.4 = is_negated;
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

impl U32SyntaxTree {
    pub fn negate(self) -> Self {
        match self {
            U32SyntaxTree::True => U32SyntaxTree::False,
            U32SyntaxTree::False => U32SyntaxTree::True,
            U32SyntaxTree::Atom(a) => {
                let mut new_atom = a.clone();
                new_atom.negate();
                U32SyntaxTree::Atom(new_atom)
            }
            U32SyntaxTree::And(a, b) => U32SyntaxTree::Nand(a, b),
            U32SyntaxTree::Nand(a, b) => U32SyntaxTree::And(a, b),
            U32SyntaxTree::Or(a, b) => U32SyntaxTree::Nor(a, b),
            U32SyntaxTree::Nor(a, b) => U32SyntaxTree::Or(a, b),
        }
    }
}

impl WhereSyntaxTree {
    /// Stringifies a `WhereSyntaxTree` for debugging purposes.
    #[allow(dead_code)]
    fn to_string_lines(&self, base_index: u8) -> Vec<String> {
        let indent_closure =
            |v: Vec<String>| v.iter().map(|s| format!("  {s}")).collect::<Vec<String>>();
        let binary_op_closure = |op: &str, a: &Box<WhereSyntaxTree>, b: &Box<WhereSyntaxTree>| {
            let b_base_index = a.index(base_index) + 1;
            let mut result = vec![format!("({}) {op}", self.index(base_index))];
            let mut left: Vec<String> = indent_closure(a.to_string_lines(base_index));
            let mut right: Vec<String> = indent_closure(b.to_string_lines(b_base_index));
            result.append(&mut left);
            result.append(&mut right);
            result
        };
        match &self {
            WhereSyntaxTree::Atom(a) => {
                vec![format!("({}) {}", self.index(base_index), a.to_string())]
            }
            WhereSyntaxTree::And(a, b) => binary_op_closure("And", a, b),
            WhereSyntaxTree::Or(a, b) => binary_op_closure("Or", a, b),
            WhereSyntaxTree::Nand(a, b) => binary_op_closure("Not And", a, b),
            WhereSyntaxTree::Nor(a, b) => binary_op_closure("Not Or", a, b),
        }
    }

    /// Stringifies a `WhereSyntaxTree` for debugging purposes.
    #[allow(dead_code)]
    pub fn to_string(&self) -> String {
        self.to_string_lines(0).join("\n")
    }

    /// Negates a `WhereSyntaxTree`.
    pub fn negate(&self) -> Self {
        match &self {
            WhereSyntaxTree::Atom(a) => {
                let mut negated_a = a.clone();
                negated_a.negate();
                WhereSyntaxTree::Atom(negated_a)
            }
            WhereSyntaxTree::And(a, b) => WhereSyntaxTree::Nand(a.clone(), b.clone()),
            WhereSyntaxTree::Nand(a, b) => WhereSyntaxTree::And(a.clone(), b.clone()),
            WhereSyntaxTree::Or(a, b) => WhereSyntaxTree::Nor(a.clone(), b.clone()),
            WhereSyntaxTree::Nor(a, b) => WhereSyntaxTree::Or(a.clone(), b.clone()),
        }
    }

    /// Returns the current node index when listing the tree nodes in reverse Polish order.
    pub fn index(&self, base_index: u8) -> u8 {
        match &self {
            WhereSyntaxTree::Atom(a) => match a.cell_type() {
                // 8 values plus 7 AND gates
                CellType::ShortString => base_index + 14,
                _ => base_index,
            },
            WhereSyntaxTree::And(a, b)
            | WhereSyntaxTree::Nand(a, b)
            | WhereSyntaxTree::Or(a, b)
            | WhereSyntaxTree::Nor(a, b) => b.index(a.index(base_index) + 1) + 1,
        }
    }

    /// Encodes a `WhereSyntaxTree` as a vector of `EncodedInstruction`s.
    pub fn encode_with_index(
        &self,
        headers: &TableHeaders,
        base_index: u8,
    ) -> Vec<EncodedInstruction> {
        match &self {
            WhereSyntaxTree::Atom(a) => a.encode(headers, base_index, false),
            WhereSyntaxTree::And(a, b)
            | WhereSyntaxTree::Nand(a, b)
            | WhereSyntaxTree::Or(a, b)
            | WhereSyntaxTree::Nor(a, b) => {
                let (which_op, negate) = match &self {
                    WhereSyntaxTree::And(_, _) => (false, false),
                    WhereSyntaxTree::Nand(_, _) => (false, true),
                    WhereSyntaxTree::Or(_, _) => (true, false),
                    WhereSyntaxTree::Nor(_, _) => (true, true),
                    WhereSyntaxTree::Atom(_) => unreachable!(),
                };
                let mut result = a.encode_with_index(headers, base_index);
                let a_index = a.index(base_index);
                let b_index = b.index(a_index + 1);
                result.append(&mut b.encode_with_index(headers, a_index + 1));
                result.push((
                    true,           // encode operator
                    a_index,        // encode left index
                    which_op,       // encode op
                    b_index as u32, // encode right index
                    negate,         // encode op
                ));
                result
            }
        }
    }

    pub fn encode(&self, headers: &TableHeaders) -> Vec<EncodedInstruction> {
        self.encode_with_index(headers, 0)
    }

    /// Encrypts a `WhereSyntaxTree`.
    ///
    /// First encodes itself, then encrypt each element of the resulting vector.
    pub fn encrypt(&self, client_key: &ClientKey, headers: &TableHeaders) -> EncryptedSyntaxTree {
        self.encode(headers)
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

/// Builds an `WhereSyntaxTree` from a `sqlparser::Expr`.  This is used to
/// discard all unnecessary data that comes along a `sqlparser::Expr`.
impl From<Expr> for WhereSyntaxTree {
    fn from(expr: Expr) -> Self {
        match expr {
            Expr::Nested(e) => Self::from(e.as_ref().to_owned()),
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr: e,
            } => Self::from(e.as_ref().to_owned()).negate(),
            Expr::UnaryOp { op, .. } => panic!("unknown unary operator {op:?}"),
            Expr::BinaryOp {
                ref left,
                ref op,
                ref right,
            } => match (left.as_ref().to_owned(), right.as_ref().to_owned()) {
                // builds an Atom from a SQL expression `column OP value`
                (Expr::Identifier(i_left), Expr::Value(v_right)) => {
                    let atom = AtomicCondition::from((i_left, op.to_owned(), v_right));
                    Self::Atom(atom)
                }
                (Expr::Identifier(i_left), Expr::Identifier(i_right))
                    if op == &BinaryOperator::Eq || op == &BinaryOperator::NotEq =>
                {
                    let atom = AtomicCondition::from((i_left, op.to_owned(), i_right));
                    Self::Atom(atom)
                }
                // recursively builds a syntax tree from a SQL expression `l OP r`
                // where OP is one of AND, OR
                // and l, r are SQL expressions
                (l, r) => {
                    let left = Self::from(l.clone());
                    let right = Self::from(r.clone());
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

pub fn build_where_syntax_tree(statement: Statement) -> WhereSyntaxTree {
    match statement {
        Statement::Query(q) => match q.body.as_ref() {
            SetExpr::Select(s) => WhereSyntaxTree::from(s.selection.clone().unwrap()),
            _ => panic!("unknown query: {q:?}"),
        },
        _ => panic!("unknown statement: {statement:?}"),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn print_query() {
        let query_path = PathBuf::from("query.txt");
        let query = build_where_syntax_tree(parse_query(query_path));

        println!("query: \n{}\n", query.to_string());
    }

    #[test]
    pub fn encode_short_string() {
        let dialect = GenericDialect {};
        let str_query = "SELECT * from table_1 WHERE some_str=\"first_line\"";
        let ast = Parser::parse_sql(&dialect, &str_query).unwrap();
        let query = build_where_syntax_tree(ast[0].clone());
        let headers = TableHeaders(vec![
            ("some_int".to_string(), CellType::U32),
            ("some_bool".to_string(), CellType::Bool),
            ("some_str".to_string(), CellType::ShortString),
        ]);
        let encoded_query = query.encode(&headers);
        if let WhereSyntaxTree::Atom(a) = query {
            println!("encoded short string: {:?}", a.value.encode());
        }
        encoded_query.iter().for_each(|a| println!("{a:?}"));
    }
}
