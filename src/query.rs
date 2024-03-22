//! Query parsing and manipulation.
//!
//! This module contains types for an internal representation of queries, methods for obtaining
//! a disjunctive normal form of the resulting syntax tree, as well as methods for encoding and
//! encrypting them.

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

/// An atomic condition of the form `column OP value`:
/// - the `String` contains the identifier of the column being tested,
/// - the `CellContent` contains the value against which it is tested.
#[derive(Clone, Debug)]
pub struct AtomicCondition {
    pub ident: String,
    pub op: ComparisonOp,
    pub value: CellContent,
}

/// An encrypted atom is the collection of:
/// 1. a column identifier (encrypted u8),
/// 2. a value (encrypted u32),
/// 3. an encrypted boolean (encrypted integer mod 2) for identifying `op`,
/// 4. an encrypted boolean (encrypted integer mod 2) for negating the atomic condition,
pub type EncryptedAtom = (RadixCiphertext, RadixCiphertext, Ciphertext, Ciphertext);

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
    /// Encodes itself into an `EncryptedAtom`, then encrypts the resulting vector.
    /// # Inputs:
    /// - `client_key` is used for encryption,
    /// - `headers` is used to get an `u8` from a column identifier.
    /// # Outputs:
    /// a vector of tuples `(FheUint8, FheUint32, FheBool, FheBool)`, each tuple being:
    /// - at index 0: the encrypted u8 identifying a column,
    /// - at index 1: the encrypted value against which the column is tested,
    /// - at index 2: an encrypted `bool` for choosing an operator. If `true` then use `<=`,
    ///     otherwise use `=`,
    /// - at index 3: an encrypted `bool` for negating the boolean result of `column OP value`.
    pub fn encrypt(&self, client_key: &ClientKey, headers: &TableHeaders) -> Vec<EncryptedAtom> {
        let mut result = Vec::<EncryptedAtom>::with_capacity(self.cell_type().len());
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
                        client_key.encrypt_radix(base_index + (i as u8), 4),
                        ct_i,
                        client_key.encrypt_one_block(0),
                        client_key.encrypt_one_block(is_negated as u64),
                    ));
                }
            }
            _ => {
                // every other type is encoded as one u32
                let u32_value = self.value.encode()[0];
                let (op, is_negated, val) = match self.op {
                    ComparisonOp::Equal => (false, false, u32_value),
                    ComparisonOp::NotEqual => (false, true, u32_value),
                    ComparisonOp::LessEqual => (true, false, u32_value),
                    ComparisonOp::GreaterThan => (true, true, u32_value), // a > b <=> not(a <= b)
                    ComparisonOp::LessThan => (true, false, u32_value - 1), // a < b <=> a <= b-1
                    ComparisonOp::GreaterEqual => (true, true, u32_value - 1), // a >= b <=> not(a <= b-1)
                };
                result.push((
                    client_key.encrypt_radix(base_index, 4),
                    client_key.encrypt_radix(val, 16),
                    client_key.encrypt_one_block(op as u64),
                    client_key.encrypt_one_block(is_negated as u64),
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

/// A simple enum holding the syntax tree to the right of the `WHERE` keyword.
#[derive(Clone, Debug)]
pub enum WhereSyntaxTree {
    Atom(AtomicCondition),
    Not(Box<WhereSyntaxTree>),
    And(Box<WhereSyntaxTree>, Box<WhereSyntaxTree>),
    Or(Box<WhereSyntaxTree>, Box<WhereSyntaxTree>),
}

/// A type alias for storing (the encryption of) a `WHERE` syntax tree in disjunctive normal form.
///
/// It is a vector of `(op, atom)` where `op` is a boolean for choosing between AND and OR,
/// and `atom` is an atomic condition.
pub type EncryptedSyntaxTree = Vec<(Ciphertext, EncryptedAtom)>;

/// Builds a `WhereSyntaxTree` from a `sqlparser::Expr`. This is used to discard all
/// unnecessary data that comes along a `sqlparser::Expr`.
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

impl WhereSyntaxTree {
    /// Stringifies a `WhereSyntaxTree` for debugging purposes.
    fn to_string_lines(&self) -> Vec<String> {
        let indent_closure =
            |v: Vec<String>| v.iter().map(|s| format!("  {s}")).collect::<Vec<String>>();
        let binary_op_closure = |op: &str, a: &Box<WhereSyntaxTree>, b: &Box<WhereSyntaxTree>| {
            let mut result = vec![String::from(op)];
            let mut left: Vec<String> = indent_closure(a.to_string_lines());
            let mut right: Vec<String> = indent_closure(b.to_string_lines());
            result.append(&mut left);
            result.append(&mut right);
            result
        };
        match self {
            WhereSyntaxTree::Atom(a) => vec![a.to_string()],
            WhereSyntaxTree::And(a, b) => binary_op_closure("And", a, b),
            WhereSyntaxTree::Or(a, b) => binary_op_closure("Or", a, b),
            WhereSyntaxTree::Not(a) => {
                let mut result = a.to_string_lines();
                result[0] = format!("Not {}", &result[0]);
                result
            }
        }
    }
    /// Stringifies a `WhereSyntaxTree` for debugging purposes.
    pub fn to_string(&self) -> String {
        self.to_string_lines().join("\n")
    }
    /// Creates a new syntax tree where the `AND` operators are at the bottom of the tree.
    /// This uses the usual distributivity relation `(a OR b) AND c = (a AND c) OR (b AND c)`.
    ///
    /// <div class="warning"> This method assumes there is no `NOT` operator in the syntax tree.
    /// Make sure to call the `propagate_negation` method beforehand. </div>
    fn distribute_and_node(&self) -> Self {
        match self {
            WhereSyntaxTree::And(a, b) => {
                let (new_a, new_b) = (a.distribute_and_node(), b.distribute_and_node());
                match (new_a, new_b) {
                    (WhereSyntaxTree::Or(a1, a2), WhereSyntaxTree::Or(b1, b2)) => {
                        let clauses = (
                            WhereSyntaxTree::And(a1.clone(), b1.clone()).distribute_and_node(),
                            WhereSyntaxTree::And(a1.clone(), b2.clone()).distribute_and_node(),
                            WhereSyntaxTree::And(a2.clone(), b1.clone()).distribute_and_node(),
                            WhereSyntaxTree::And(a2.clone(), b2.clone()).distribute_and_node(),
                        );
                        WhereSyntaxTree::Or(
                            Box::new(WhereSyntaxTree::Or(
                                Box::new(clauses.0),
                                Box::new(clauses.1),
                            )),
                            Box::new(WhereSyntaxTree::Or(
                                Box::new(clauses.2),
                                Box::new(clauses.3),
                            )),
                        )
                    }
                    (WhereSyntaxTree::Or(a1, a2), some_tree) => {
                        let b_clone = Box::new(some_tree.clone());
                        let clauses = (
                            WhereSyntaxTree::And(a1.clone(), b_clone.clone()).distribute_and_node(),
                            WhereSyntaxTree::And(a2.clone(), b_clone).distribute_and_node(),
                        );
                        WhereSyntaxTree::Or(Box::new(clauses.0), Box::new(clauses.1))
                    }
                    (some_tree, WhereSyntaxTree::Or(b1, b2)) => {
                        let a_clone = Box::new(some_tree.clone());
                        let clauses = (
                            WhereSyntaxTree::And(a_clone.clone(), b1).distribute_and_node(),
                            WhereSyntaxTree::And(a_clone, b2).distribute_and_node(),
                        );
                        WhereSyntaxTree::Or(Box::new(clauses.0), Box::new(clauses.1))
                    }
                    (a1, b1) => WhereSyntaxTree::And(Box::new(a1), Box::new(b1)),
                }
            }
            WhereSyntaxTree::Or(a, b) => WhereSyntaxTree::Or(
                Box::new(a.distribute_and_node()),
                Box::new(b.distribute_and_node()),
            ),
            WhereSyntaxTree::Not(_) => panic!("NOT gate encountered during AND distributivity."),
            WhereSyntaxTree::Atom(_) => self.clone(),
        }
    }
    /// Propagates negations down the syntax tree, into the atomic conditions. This results in
    /// a syntax tree without any `NOT` operators.
    fn propagate_negation(&self, negate: bool) -> Self {
        match self {
            WhereSyntaxTree::Not(s) => s.propagate_negation(!negate),
            WhereSyntaxTree::Atom(a) => {
                if negate {
                    WhereSyntaxTree::Atom(a.negate())
                } else {
                    WhereSyntaxTree::Atom(a.clone())
                }
            }
            WhereSyntaxTree::And(a, b) => {
                // recursively propagate negation
                let new_a = a.propagate_negation(negate);
                let new_b = b.propagate_negation(negate);
                if negate {
                    WhereSyntaxTree::Or(Box::new(new_a), Box::new(new_b))
                } else {
                    WhereSyntaxTree::And(Box::new(new_a), Box::new(new_b))
                }
            }
            WhereSyntaxTree::Or(a, b) => {
                // recursively propagate negation
                let new_a = a.propagate_negation(negate);
                let new_b = b.propagate_negation(negate);
                if negate {
                    WhereSyntaxTree::And(Box::new(new_a), Box::new(new_b))
                } else {
                    WhereSyntaxTree::Or(Box::new(new_a), Box::new(new_b))
                }
            }
        }
    }
    /// Creates an equivalent syntax tree in disjunctive normal form.
    pub fn disjunctive_normal_form(&self) -> Self {
        // 1. negations are only allowed in the leaves of the syntax tree,
        // 2. an And node cannot be a parent of an Or node
        self.propagate_negation(false).distribute_and_node()
    }
    /// Encrypts the syntax tree as a vector of elements `(encrypted_atom, op)` where
    /// `op` is a boolean:
    /// - `op == true`: apply `AND` operator,
    /// - `op == false`: apply `OR` operator.
    /// The final element's `op` is ignored.
    ///
    /// <div class="warning">This method assumes that the syntax tree is in disjunctive normal form.</div>
    pub fn encrypt(&self, client_key: &ClientKey, headers: &TableHeaders) -> EncryptedSyntaxTree {
        match self {
            WhereSyntaxTree::Atom(a) => a
                .encrypt(client_key, headers)
                .into_iter()
                .map(|atom| (client_key.encrypt_bool(false).into_inner(), atom))
                .collect::<Vec<_>>(),
            WhereSyntaxTree::And(a, b) => {
                let mut result = a.encrypt(client_key, headers);
                let left_length = result.len();
                result[left_length - 1].0 = client_key.encrypt_bool(true).into_inner();
                result.append(&mut b.encrypt(client_key, headers));
                result
            }
            WhereSyntaxTree::Or(a, b) => {
                let mut result = a.encrypt(client_key, headers);
                let left_length = result.len();
                result[left_length - 1].0 = client_key.encrypt_bool(false).into_inner();
                result.append(&mut b.encrypt(client_key, headers));
                result
            }
            WhereSyntaxTree::Not(_) => panic!("Encountered a NOT operator during encryption."),
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
