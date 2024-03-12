use crate::{CellContent, CellType, TableHeaders};
use sqlparser::ast::{BinaryOperator, Expr, Ident, UnaryOperator, Value};
use std::str::FromStr;
use tfhe::prelude::*;
use tfhe::{ClientKey, FheBool, FheUint32, FheUint8};

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

/// An atomic condition of the form `column OP value`:
/// - the `String` contains the identifier of the column being tested,
/// - the `CellContent` contains the value against which it is tested.
#[derive(Clone, Debug)]
pub struct AtomicCondition {
    pub ident: String,
    pub op: ComparisonOp,
    pub value: CellContent,
}

type EncryptedAtom = (FheUint8, FheUint32, FheBool, FheBool);

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
    /// Encodes itself into an `EncryptedAtom`, then encrypts the resulting vector.
    /// # Inputs:
    /// - `client_key` is used for encryption,
    /// - `headers` is used to get an `u8` from a column identifier.
    /// # Outputs:
    /// a vector of tuples `(FheUint8, FheUint8, FheBool, FheBool)`, each tuple being:
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
                        FheUint8::encrypt(base_index + (i as u8), client_key),
                        ct_i,
                        FheBool::encrypt(false, client_key),
                        FheBool::encrypt(is_negated, client_key),
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
                    FheUint8::encrypt(base_index, client_key),
                    FheUint32::encrypt(val, client_key),
                    FheBool::encrypt(op, client_key),
                    FheBool::encrypt(is_negated, client_key),
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

/// A simple enum holding the syntax tree to the right of the `WHERE` keyword
#[derive(Clone, Debug)]
pub enum WhereSyntaxTree {
    Atom(AtomicCondition),
    Not(Box<WhereSyntaxTree>),
    And(Box<WhereSyntaxTree>, Box<WhereSyntaxTree>),
    Or(Box<WhereSyntaxTree>, Box<WhereSyntaxTree>),
}

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
    /// Creates a new syntax tree where the `AND` operators are at the bottom of the tree.
    /// This uses the usual distributivity relation `(a OR b) AND c = (a AND c) OR (b AND c)`.
    /// *WARNING* This method assumes there is no `NOT` operator in the syntax tree. Make sure to
    /// call the `propagate_negation` method beforehand.
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
            WhereSyntaxTree::Not(a) => panic!("NOT gate encountered during AND distributivity."),
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
    pub fn conjuntive_normal_form(&self) -> Self {
        // negations are only allowed in the leaves of the syntax tree,
        // an And node cannot be a parent of an Or node
        self.propagate_negation(false).distribute_and_node()
    }
    /// Encrypts the syntax tree as a vector of elements `(encrypted_atom, op)` where
    /// `op` is a boolean:
    /// - `op == true`: apply `AND` operator,
    /// - `op == false`: apply `OR` operator.
    /// The final element's `op` is ignored.
    /// *WARNING* This method assumes that the syntax tree is in conjunctive normal form.
    pub fn encrypt(
        &self,
        client_key: &ClientKey,
        headers: &TableHeaders,
    ) -> Vec<(EncryptedAtom, FheBool)> {
        match self {
            WhereSyntaxTree::Atom(a) => a
                .encrypt(client_key, headers)
                .into_iter()
                .map(|atom| (atom, FheBool::encrypt(true, client_key)))
                .collect::<Vec<_>>(),
            WhereSyntaxTree::And(a, b) => {
                let mut result = a.encrypt(client_key, headers);
                let left_length = result.len();
                result[left_length - 1].1 = FheBool::encrypt(true, client_key);
                result.append(&mut b.encrypt(client_key, headers));
                result
            }
            WhereSyntaxTree::Or(a, b) => {
                let mut result = a.encrypt(client_key, headers);
                let left_length = result.len();
                result[left_length - 1].1 = FheBool::encrypt(false, client_key);
                result.append(&mut b.encrypt(client_key, headers));
                result
            }
            WhereSyntaxTree::Not(_) => panic!("Encountered a NOT operator during encryption."),
        }
    }
}
