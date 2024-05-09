//! Implements a (small) subset of a SQL management system.
//!
//! Adds [`run_clear_query`](Database::run_clear_query) method to the
//! [`Database`] struct.

use sqlparser::ast::{Expr, SelectItem};
use std::collections::HashMap;

use crate::query::ClearQuery;
use crate::tables::Database;
use crate::{ComparisonOp, U64Atom, U64SyntaxTree};

impl Database {
    pub fn run_clear_query(&self, query: ClearQuery) -> HashMap<String, u32> {
        let ClearQuery {
            distinct,
            projection: _,
            sql_projection,
            table_selection,
            where_condition,
        } = query;

        let table = &self.tables[table_selection as usize].1;

        let mut result: HashMap<String, u32> = HashMap::new();

        for record in &table.content {
            let encoded_record = record
                .iter()
                .flat_map(|cell| cell.encode())
                .collect::<Vec<u64>>();
            if evaluate_condition_on_raw_record(&where_condition, &encoded_record) {
                let mut key: Vec<String> = Vec::new();

                for s in &sql_projection {
                    match s {
                        SelectItem::UnnamedExpr(Expr::Identifier(id)) => {
                            let ident = id.value.clone();
                            let index = table
                                .headers
                                .index_of(ident.clone())
                                .expect("Column identifier {ident} does not exist")
                                as usize;
                            key.push(record[index].to_string())
                        }
                        SelectItem::Wildcard(_) => {
                            key = vec![record
                                       .iter()
                                       .map(|cell| cell.to_string())
                                       .collect::<Vec<String>>()
                                       .join(",")];
                            break;
                        }
                        s => panic!("Unsupported SelectItem: {s:?}"),
                    }
                }

                let key = key.join(",");

                if let Some(u) = result.get_mut(&key) {
                    if !distinct {
                        *u += 1;
                    }
                } else {
                    result.insert(key, 1);
                }
            }
        }

        result
    }
}

fn evaluate_condition_on_raw_record(condition: &U64SyntaxTree, record: &[u64]) -> bool {
    let eval = |cond| evaluate_condition_on_raw_record(cond, record);
    match condition {
        U64SyntaxTree::False => false,
        U64SyntaxTree::True => true,
        U64SyntaxTree::Atom(U64Atom { index, op, value }) => {
            let (left, right) = (record[*index as usize], *value);
            match op {
                ComparisonOp::LessThan => left < right,
                ComparisonOp::LessEqual => left <= right,
                ComparisonOp::Equal => left == right,
                ComparisonOp::GreaterEqual => left >= right,
                ComparisonOp::GreaterThan => left > right,
                ComparisonOp::NotEqual => left != right,
            }
        }
        U64SyntaxTree::And(a, b) => eval(a) && eval(b),
        U64SyntaxTree::Nand(a, b) => !(eval(a) && eval(b)),
        U64SyntaxTree::Or(a, b) => eval(a) || eval(b),
        U64SyntaxTree::Nor(a, b) => !(eval(a) || eval(b)),
    }
}
