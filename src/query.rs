//! Query parsing and manipulation.
//!
//! This module contains types for an internal representation of queries, as
//! well as methods for encoding and encrypting them.

use crate::{CellContent, CellType, TableHeaders};

use egg::{rewrite as rw, *};

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
        self.encode_with_index(headers, 0)
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
            } => Self::from((base_index, e.as_ref().to_owned())).negate(),
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
                    let left = Self::from((base_index, l.clone()));
                    let right = Self::from((left.index(base_index) + 1, r.clone()));
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

define_language! {
    /// defines a simple language to model queries, then uses the `egg` library
    /// to optimize them.
    pub enum QueryLanguage {
        "true" = True,
        "false" = False,

        "AND" = And([Id; 2]),
        "OR" = Or([Id; 2]),
        "NOT" = Not(Id),

        Num(u32),

        "=" = Eq([Id; 2]),
        "<=" = Leq([Id; 2]),
        "<" = Lt([Id; 2]),

        "min" = Min([Id; 2]),
        "max" = Max([Id; 2]),

        Symbol(Symbol),
    }
}

/// Returns a vector containing all the rewrite rules for `QueryLanguage`.
pub fn rules() -> Vec<Rewrite> {
    let trivial_bound_right = format!("(<= ?x {})", u32::MAX);
    let trivial_bound_as_str = trivial_bound_right.as_str();
    let mut rules: Vec<Rewrite> = vec![];
    // not rules
    rules.append(&mut rw!("not-true"; "(NOT true)" <=> "false"));
    rules.append(&mut rw!("not-false"; "(NOT false)" <=> "true"));
    rules.append(&mut rw!("double-negation"; "(NOT (NOT ?x))" <=> "?x"));
    // and rules
    rules.push(rw!("and-false"; "(AND ?x false)" => "false"));
    rules.push(rw!("and-excluded-mid"; "(AND ?x (NOT ?x))" => "false"));
    rules.append(&mut rw!("and-true"; "(AND ?x true)" <=> "?x"));
    rules.append(&mut rw!("associate-and"; "(AND ?x (AND ?y ?z))" <=> "(AND (AND ?x ?y) ?z)"));
    rules.append(&mut rw!("commute-and"; "(AND ?x ?y)" <=> "(AND ?y ?x)"));
    rules.append(&mut rw!("idempotent-and"; "(AND ?x ?x)" <=> "?x"));
    // or rules
    rules.push(rw!("or-excluded-mid"; "(OR ?x (NOT ?x))" => "true"));
    rules.push(rw!("or-true"; "(OR ?x true)" => "true"));
    rules.append(&mut rw!("or-false"; "(OR ?x false)" <=> "?x"));
    rules.append(&mut rw!("associate-or"; "(OR ?x (OR ?y ?z))" <=> "(OR (OR ?x ?y) ?z)"));
    rules.append(&mut rw!("commute-or"; "(OR ?x ?y)" <=> "(OR ?y ?x)"));
    rules.append(&mut rw!("idempotent-or"; "(OR ?x ?x)" <=> "?x"));
    // and-or-not rules
    rules.append(
        &mut rw!("distribute-or"; "(AND ?x (OR ?y ?z))" <=> "(OR (AND ?x ?y) (AND ?x ?z))"),
    );
    rules.append(
        &mut rw!("distribute-and"; "(OR ?x (AND ?y ?z))" <=> "(AND (OR ?x ?y) (OR ?x ?z))"),
    );
    rules.append(&mut rw!("de-morgan"; "(NOT (AND ?x ?y))" <=> "(OR (NOT ?x) (NOT ?y))"));
    // atom rules
    rules.append(&mut rw!("neq-lt-or-gt"; "(NOT (= ?x ?y))" <=> "(OR (< ?x ?y) (NOT (<= ?x ?y)))"));
    rules.append(&mut rw!("leq-and"; "(AND (<= ?x ?y) (<= ?x ?z))" <=> "(<= ?x (min ?y ?z))"));
    rules.append(&mut rw!("leq-or"; "(OR (<= ?x ?y) (<= ?x ?z))" <=> "(<= ?x (max ?y ?z))"));
    rules.push(rw!("bound-left"; "(< ?x 0)" => "false"));
    rules.push(rw!("bound-right"; "(<= ?x 4294967295)" => "true")); // hardcoding u32::MAX

    rules
}

pub type EGraph = egg::EGraph<QueryLanguage, ConstantFold>;
pub type Rewrite = egg::Rewrite<QueryLanguage, ConstantFold>;

/// Defines how to handle constants when simplifying queries.
#[derive(Default)]
pub struct ConstantFold;
impl Analysis<QueryLanguage> for ConstantFold {
    type Data = Option<(u32, PatternAst<QueryLanguage>)>;

    fn make(egraph: &EGraph, enode: &QueryLanguage) -> Self::Data {
        let x = |i: &Id| egraph[*i].data.as_ref().map(|d| d.0);
        Some(match enode {
            QueryLanguage::Num(c) => (*c, format!("{}", c).parse().unwrap()),
            QueryLanguage::Max([a, b]) => (
                x(a)?.max(x(b)?),
                format!("(max {} {})", x(a)?, x(b)?).parse().unwrap(),
            ),
            QueryLanguage::Min([a, b]) => (
                x(a)?.min(x(b)?),
                format!("(min {} {})", x(a)?, x(b)?).parse().unwrap(),
            ),
            _ => return None,
        })
    }

    fn merge(&mut self, to: &mut Self::Data, from: Self::Data) -> DidMerge {
        merge_option(to, from, |a, b| {
            assert_eq!(a.0, b.0, "Merged non-equal constants");
            DidMerge(false, false)
        })
    }

    fn modify(egraph: &mut EGraph, id: Id) {
        let data = egraph[id].data.clone();
        if let Some((c, pat)) = data {
            if egraph.are_explanations_enabled() {
                egraph.union_instantiations(
                    &pat,
                    &format!("{}", c).parse().unwrap(),
                    &Default::default(),
                    "constant_fold".to_string(),
                );
            } else {
                let added = egraph.add(QueryLanguage::Num(c));
                egraph.union(id, added);
            }
            // to not prune, comment this out
            egraph[id].nodes.retain(|n| n.is_leaf());

            #[cfg(debug_assertions)]
            egraph[id].assert_unique_leaves();
        }
    }
}

/// parse an expression, simplify it using egg, and pretty print it back out
pub fn simplify(s: &str) -> String {
    // parse the expression, the type annotation tells it which Language to use
    let expr: RecExpr<QueryLanguage> = s.parse().unwrap();

    // simplify the expression using a Runner, which creates an e-graph with
    // the given expression and runs the given rules over it
    let runner = Runner::<QueryLanguage, ConstantFold, ()>::default()
        .with_expr(&expr)
        .run(&rules());

    // the Runner knows which e-class the expression given with `with_expr` is in
    let root = runner.roots[0];

    // use an Extractor to pick the best element of the root eclass
    let extractor = Extractor::new(&runner.egraph, AstSize);
    let (best_cost, best) = extractor.find_best(root);
    println!("Simplified {} to {} with cost {}", expr, best, best_cost);
    best.to_string()
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
