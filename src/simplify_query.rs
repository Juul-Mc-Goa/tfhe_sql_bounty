use egg::{rewrite as rw, *};

use crate::{ComparisonOp, U64Atom, U64SyntaxTree};

define_language! {
    /// defines a simple language to model queries, then uses the `egg` library
    /// to optimize them.
    pub enum QueryLanguage {
        "true" = True,
        "false" = False,

        "AND" = And([Id; 2]),
        "OR" = Or([Id; 2]),
        "NOT" = Not(Id),

        Num(u64),

        "=" = Eq([Id; 2]),
        "<=" = Leq([Id; 2]),
        "<" = Lt([Id; 2]),

        // operators to handle constants
        "min" = Min([Id; 2]),
        "max" = Max([Id; 2]),
        "pred" = Pred(Id),

        Symbol(Symbol),
    }
}

/// Checks if a variable is not zero.
fn is_not_zero(var: &'static str) -> impl Fn(&mut EGraph, Id, &Subst) -> bool {
    let var = var.parse().unwrap();
    let zero = QueryLanguage::Num(0);
    move |egraph, _, subst| !egraph[subst[var]].nodes.contains(&zero)
}

/// Checks if two variables are not equal.
fn are_not_equal(
    var1: &'static str,
    var2: &'static str,
) -> impl Fn(&mut EGraph, Id, &Subst) -> bool {
    let condition_eq = ConditionEqual::parse(var1, var2);
    move |egraph, eclass, subst| !condition_eq.check(egraph, eclass, subst)
}

/// Returns a vector containing all the rewrite rules for `QueryLanguage`.
pub fn rules() -> Vec<Rewrite> {
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
    // mixed rules
    rules.append(
        &mut rw!("distribute-or"; "(AND ?x (OR ?y ?z))" <=> "(OR (AND ?x ?y) (AND ?x ?z))"),
    );
    rules.append(
        &mut rw!("distribute-and"; "(OR ?x (AND ?y ?z))" <=> "(AND (OR ?x ?y) (OR ?x ?z))"),
    );
    rules.append(&mut rw!("de-morgan"; "(NOT (AND ?x ?y))" <=> "(OR (NOT ?x) (NOT ?y))"));
    // atom rules
    rules.push(
        rw!("exclusive-eq"; "(AND (= ?x ?y) (= ?x ?z))" => "false" if are_not_equal("?y", "?z")),
    );
    rules.append(&mut rw!("lt-leq-pred"; "(<= ?x (pred ?y))" <=> "(< ?x ?y)" if is_not_zero("?y")));
    rules.append(&mut rw!("leq-lt-eq"; "(<= ?x ?y)" <=> "(OR (= ?x ?y) (< ?x ?y))"));
    rules.append(&mut rw!("neq-lt-or-gt"; "(NOT (= ?x ?y))" <=> "(OR (< ?x ?y) (NOT (<= ?x ?y)))"));
    rules.append(&mut rw!("leq-and"; "(AND (<= ?x ?y) (<= ?x ?z))" <=> "(<= ?x (min ?y ?z))"));
    rules.append(&mut rw!("leq-or"; "(OR (<= ?x ?y) (<= ?x ?z))" <=> "(<= ?x (max ?y ?z))"));
    rules.push(rw!("bound-left"; "(< ?x 0)" => "false"));
    rules.push(rw!("bound-right"; "(<= ?x 18446744073709551615)" => "true")); // hardcoding u64::MAX

    rules
}

/// Defines how to handle constants when simplifying queries.
#[derive(Default)]
pub struct ConstantFold;
impl Analysis<QueryLanguage> for ConstantFold {
    type Data = Option<(u64, PatternAst<QueryLanguage>)>;

    fn make(egraph: &EGraph, enode: &QueryLanguage) -> Self::Data {
        let x = |i: &Id| egraph[*i].data.as_ref().map(|d| d.0);
        Some(match enode {
            QueryLanguage::Num(c) => (*c, format!("{}", c).parse().unwrap()),
            QueryLanguage::Pred(c) => (x(c)? - 1, format!("{}", x(c)? - 1).parse().unwrap()),
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

pub type EGraph = egg::EGraph<QueryLanguage, ConstantFold>;
pub type Rewrite = egg::Rewrite<QueryLanguage, ConstantFold>;

/// Defines the cost function to minimize.
///
/// + numerical constants are considered to have a cost of zero,
/// + `NOT: a -> 1+a` is given a cost of `1.0`,
/// + operations on constants are given a small non-zero cost,
/// + every other operator requires some PBS, so is given a cost of `100.0`.
struct CostFn;
impl CostFunction<QueryLanguage> for CostFn {
    type Cost = f64;
    fn cost<C>(&mut self, enode: &QueryLanguage, mut costs: C) -> Self::Cost
    where
        C: FnMut(Id) -> Self::Cost,
    {
        let op_cost = match enode {
            QueryLanguage::True | QueryLanguage::False | QueryLanguage::Num(_) => 0.0,
            QueryLanguage::Not(_) => 1.0,
            QueryLanguage::Min([_, _]) | QueryLanguage::Max([_, _]) | QueryLanguage::Pred(_) => 1.0,
            _ => 100.0,
        };
        enode.fold(op_cost, |sum, id| sum + costs(id))
    }
}

/// parse an expression, simplify it using egg, and pretty print it back out
#[allow(dead_code)]
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
    let extractor = Extractor::new(&runner.egraph, CostFn);
    let (_, best) = extractor.find_best(root);
    best.to_string()
}

impl U64SyntaxTree {
    /// Builds an `egg::RecExpr`, to be used with `self.simplify`
    pub fn build_recexpr(&self, acc: &mut RecExpr<QueryLanguage>) -> Id {
        match self {
            U64SyntaxTree::True => acc.add(QueryLanguage::True),
            U64SyntaxTree::False => acc.add(QueryLanguage::False),
            U64SyntaxTree::Atom(a) => {
                let index = QueryLanguage::Symbol(format!("id_{}", a.index).into());
                let val = QueryLanguage::Num(a.value);
                let (id_index, id_val) = (acc.add(index), acc.add(val));
                let new_node = match a.op {
                    ComparisonOp::Equal => QueryLanguage::Eq([id_index, id_val]),
                    ComparisonOp::LessEqual => QueryLanguage::Leq([id_index, id_val]),
                    ComparisonOp::LessThan => QueryLanguage::Lt([id_index, id_val]),
                    ComparisonOp::GreaterThan => {
                        let leq_id = acc.add(QueryLanguage::Leq([id_index, id_val]));
                        QueryLanguage::Not(leq_id)
                    }
                    ComparisonOp::GreaterEqual => {
                        let lt_id = acc.add(QueryLanguage::Lt([id_index, id_val]));
                        QueryLanguage::Not(lt_id)
                    }
                    ComparisonOp::NotEqual => {
                        let eq_id = acc.add(QueryLanguage::Eq([id_index, id_val]));
                        QueryLanguage::Not(eq_id)
                    }
                };
                acc.add(new_node)
            }
            U64SyntaxTree::And(a, b) => {
                let id_left = a.build_recexpr(acc);
                let id_right = b.build_recexpr(acc);
                acc.add(QueryLanguage::And([id_left, id_right]))
            }
            U64SyntaxTree::Or(a, b) => {
                let id_left = a.build_recexpr(acc);
                let id_right = b.build_recexpr(acc);
                acc.add(QueryLanguage::Or([id_left, id_right]))
            }
            U64SyntaxTree::Nand(a, b) => {
                let id_left = a.build_recexpr(acc);
                let id_right = b.build_recexpr(acc);
                let id_and = acc.add(QueryLanguage::And([id_left, id_right]));
                acc.add(QueryLanguage::Not(id_and))
            }
            U64SyntaxTree::Nor(a, b) => {
                let id_left = a.build_recexpr(acc);
                let id_right = b.build_recexpr(acc);
                let id_and = acc.add(QueryLanguage::Or([id_left, id_right]));
                acc.add(QueryLanguage::Not(id_and))
            }
        }
    }

    /// Builds a `U64SyntaxTree` from a root node `n` and an expression `e`.
    fn from_root_and_expr(n: &QueryLanguage, e: &RecExpr<QueryLanguage>) -> Self {
        match n {
            QueryLanguage::True => U64SyntaxTree::True,
            QueryLanguage::False => U64SyntaxTree::False,
            QueryLanguage::And([l, r]) => U64SyntaxTree::And(
                Box::new(Self::from_root_and_expr(&e[*l], e)),
                Box::new(Self::from_root_and_expr(&e[*r], e)),
            ),
            QueryLanguage::Or([l, r]) => U64SyntaxTree::Or(
                Box::new(Self::from_root_and_expr(&e[*l], e)),
                Box::new(Self::from_root_and_expr(&e[*r], e)),
            ),
            QueryLanguage::Not(a) => Self::from_root_and_expr(&e[*a], e).negate(),
            QueryLanguage::Eq([l, r]) | QueryLanguage::Leq([l, r]) | QueryLanguage::Lt([l, r]) => {
                let op = match n {
                    QueryLanguage::Eq(_) => ComparisonOp::Equal,
                    QueryLanguage::Leq(_) => ComparisonOp::LessEqual,
                    QueryLanguage::Lt(_) => ComparisonOp::LessThan,
                    _ => unreachable!(),
                };
                match (&e[*l], &e[*r]) {
                    (QueryLanguage::Symbol(s), QueryLanguage::Num(u)) => {
                        let str_index = &s.as_str()[3..];
                        let index = str::parse::<u8>(str_index)
                            .expect(format!("Could not parse id '{str_index}'").as_str());
                        let value = *u;
                        U64SyntaxTree::Atom(U64Atom { index, op, value })
                    }
                    _ => panic!("unsupported atom: {n}"),
                }
            }
            _ => panic!("unsupported syntax tree: {n}"),
        }
    }

    /// Builds an `U64SyntaxTree` from a `RecExpr<QueryLanguage>`.
    pub fn from_recexpr(expr: RecExpr<QueryLanguage>) -> Self {
        // the root node is at last position because of the required invariant
        // that a node's children must be before the node itself
        let root_node = expr.as_ref().last().unwrap();
        Self::from_root_and_expr(root_node, &expr)
    }

    /// Simplifies a `U64SyntaxTree` by converting it to a `RecExpr`,
    /// simplifying the result, and converting back to `U64SyntaxTree`.
    pub fn simplify(&self) -> Self {
        let mut expr = RecExpr::<QueryLanguage>::default();
        let _ = self.build_recexpr(&mut expr);
        // simplify the expression using a Runner, which creates an e-graph with
        // the given expression and runs the given rules over it
        let runner = Runner::<QueryLanguage, ConstantFold, ()>::default()
            .with_expr(&expr)
            .run(&rules());

        // the Runner knows which e-class the expression given with `with_expr` is in
        let root = runner.roots[0];

        // use an Extractor to pick the best element
        let extractor = Extractor::new(&runner.egraph, CostFn);
        let (_, best) = extractor.find_best(root);
        Self::from_recexpr(best)
    }
}
