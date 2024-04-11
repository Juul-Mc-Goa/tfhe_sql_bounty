use egg::{rewrite as rw, *};

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

        // operators to handle constants
        "min" = Min([Id; 2]),
        "max" = Max([Id; 2]),
        "pred" = Pred(Id),

        Symbol(Symbol),
    }
}

// This returns a function that implements Condition
fn is_not_zero(var: &'static str) -> impl Fn(&mut EGraph, Id, &Subst) -> bool {
    let var = var.parse().unwrap();
    let zero = QueryLanguage::Num(0);
    move |egraph, _, subst| !egraph[subst[var]].nodes.contains(&zero)
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
    rules.append(&mut rw!("lt-leq-pred"; "(<= ?x (pred ?y))" <=> "(< ?x ?y)" if is_not_zero("?y")));
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
