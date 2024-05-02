use rayon::prelude::*;
use tfhe::integer::wopbs::WopbsKey;
use tfhe::integer::{RadixCiphertext, ServerKey};
use tfhe::shortint::{Ciphertext, WopbsParameters};

use crate::cipher_structs::{EntryLUT, FheBool, QueryLUT};
use crate::{Database, Table, TableHeaders};
use crate::{EncryptedQuery, EncryptedSyntaxTree};

/// A result of a SQL query.
pub struct EncryptedResult<'a> {
    /// Contains one encrypted boolean for each entry.
    pub is_entry_in_result: Vec<Ciphertext>,
    /// Contains one encrypted boolean for each column.
    pub projection: Vec<Ciphertext>,
    /// Contains one encrypted `u64` for each cell.
    pub content: Vec<Vec<RadixCiphertext>>,
    pub server_key: &'a ServerKey,
    pub shortint_server_key: &'a tfhe::shortint::ServerKey,
}

impl<'a> EncryptedResult<'a> {
    /// Resize an `EncryptedResult` to a given `length` and `width`.
    pub fn resize(&mut self, length: u8, width: u8) {
        let (length, width) = (length as usize, width as usize);
        let value = self.shortint_server_key.create_trivial(0);
        let value_radix: RadixCiphertext = self.server_key.create_trivial_zero_radix(32);

        self.is_entry_in_result.resize(length, value.clone());
        self.projection.resize(width, value.clone());

        self.content
            .iter_mut()
            .for_each(|entry| entry.resize(width, value_radix.clone()));
        self.content.resize(length, vec![value_radix; width]);
    }

    /// Multiply each stored `Ciphertext` or `RadixCiphertext` by a given `Ciphertext`.
    pub fn block_mul_assign(&mut self, ct: &Ciphertext) {
        self.is_entry_in_result
            .par_iter_mut()
            .for_each(|entry_bool: &mut Ciphertext| {
                self.shortint_server_key.mul_assign(entry_bool, ct)
            });
        self.projection
            .par_iter_mut()
            .for_each(|column_bool: &mut Ciphertext| {
                self.shortint_server_key.mul_assign(column_bool, ct)
            });
        self.content.par_iter_mut().for_each(|entry| {
            entry.par_iter_mut().for_each(|cell: &mut RadixCiphertext| {
                self.server_key.block_mul_assign_parallelized(cell, ct, 0)
            })
        });
    }

    /// Add two `EncryptedResult`s, the result is stored in the first one.
    ///
    /// Used to `XOR` two results.
    pub fn add_assign(&mut self, other: &EncryptedResult) {
        assert_eq!(
            self.is_entry_in_result.len(),
            other.is_entry_in_result.len()
        );
        assert_eq!(self.projection.len(), other.projection.len());

        let add_booleans = |left: &mut Vec<Ciphertext>, right: &[Ciphertext]| {
            for (self_bool, other_bool) in left.iter_mut().zip(right.iter()) {
                self.shortint_server_key.add_assign(self_bool, other_bool)
            }
        };

        add_booleans(&mut self.is_entry_in_result, &other.is_entry_in_result);
        add_booleans(&mut self.projection, &other.projection);

        for (self_entry, other_entry) in self.content.iter_mut().zip(other.content.iter()) {
            for (self_cell, other_cell) in self_entry.iter_mut().zip(other_entry.iter()) {
                self.server_key
                    .add_assign_parallelized(self_cell, other_cell)
            }
        }
    }
}

/// An encoded representation of a SQL table, plus a bunch of server keys used
/// during computations.
///
/// Each entry is stored as a `Vec<u64>`. A table is a vector of entries.
pub struct TableQueryRunner<'a> {
    pub headers: TableHeaders,
    pub content: Vec<Vec<u64>>,
    pub server_key: &'a ServerKey,
    pub shortint_server_key: &'a tfhe::shortint::ServerKey,
    pub wopbs_key: &'a WopbsKey,
    pub wopbs_parameters: WopbsParameters,
}

impl<'a> TableQueryRunner<'a> {
    pub fn new(
        table: Table,
        server_key: &'a ServerKey,
        shortint_server_key: &'a tfhe::shortint::ServerKey,
        wopbs_key: &'a WopbsKey,
        wopbs_parameters: WopbsParameters,
    ) -> Self {
        Self {
            headers: table.headers.clone(),
            content: table
                .content
                .iter()
                .map(|entry| entry.iter().flat_map(|cell| cell.encode()).collect())
                .collect::<Vec<Vec<u64>>>(),
            server_key,
            shortint_server_key,
            wopbs_key,
            wopbs_parameters,
        }
    }

    /// Runs an encrypted query on a given entry.
    ///
    /// # Inputs
    /// - `entry: &Vec<u64>` an encoded entry,
    /// - `query: &EncryptedSyntaxTree` an encrypted `SELECT` query,
    /// - `query_lut: &mut QueryLUT` an updatable, hidden lookup table.
    /// # Output
    /// A `Ciphertext` encrypting a boolean that answers the question: "Is this
    /// entry selected by the query?"
    ///
    /// The encrypted boolean is actually an integer modulo 2, so that:
    /// - `a AND b` becomes `a*b`,
    /// - `a XOR b` becomes `a+b`,
    /// - `a OR b` becomes `a+b+a*b`,
    /// - `NOT a` becomes `1+a`.
    ///
    /// Then the boolean formulas are simplified so as to minimize the number of
    /// multiplications, using the fact that addition is much faster than PBS.
    /// We also use that:
    ///
    /// $(a \lt b) \text{ XOR } (a = b) \iff a \leq b$.
    ///
    /// # Simplification of the boolean formulas:
    ///
    /// We first write:
    /// ```
    /// result_bool:
    ///   | if is_node: node_bool XOR negate
    ///   | else:       atom_bool XOR negate
    /// node_bool:
    ///   | if which_op: node_left OR  node_right
    ///   | else:        node_left AND node_right
    /// atom_bool:
    ///   | if which_op: val_left <= val_right
    ///   | else:        val_left == val_right
    /// ```
    /// and write the formula for a cmux using `+,*`:
    /// ```
    /// cmux(choice, true_case, false_case) = false_case + choice * (true_case + false_case)
    /// ```
    /// using that `2 * false_case = 0` mod 2.
    /// We thus get:
    /// ```
    /// result_bool = atom_bool + is_node * (node_bool + atom_bool) + negate
    /// atom_bool = is_eq + which_op * (is_leq + is_eq)
    ///           = is_eq + which_op * is_lt
    /// ```
    /// ```
    /// // see crate-level documentation for how we get this formula
    /// node_bool = (node_left + which_op) * (node_right + which_op) + which_op
    /// ```
    /// Where `is_lt, is_eq, is_leq` are the boolean result of:
    /// 1. `val_left < val_right`
    /// 2. `val_left == val_right`
    /// 3. `val_left <= val_right`
    ///
    /// Thus only 3 multiplications are required: one for each of the variables
    /// `atom_bool, node_bool, result_bool`.
    ///
    /// # Total number of PBS required
    /// 1. One for retrieving the value associated to an encrypted column identifier,
    /// 2. Two for evaluating `is_eq` and `is_lt`,
    /// 3. Two for retrieving `node_left` and `node_right`,
    /// 4. Three for computing `result_bool`.
    ///
    /// So a total of 8 PBS for each `EncryptedInstruction`.
    fn run_query_on_entry(
        &'a self,
        entry: &[u64],
        query: &'a EncryptedSyntaxTree,
        // query_lut: &mut QueryLUT,
    ) -> FheBool {
        let sk = self.server_key;
        let shortint_sk = self.shortint_server_key;
        let inner_wopbs = self.wopbs_key.clone().into_raw_parts();

        let entry_lut = EntryLUT::new(entry, sk, self.wopbs_key, &inner_wopbs);
        let mut query_lut: QueryLUT<'_> = QueryLUT::new(
            query.len(),
            shortint_sk,
            &inner_wopbs,
            self.wopbs_parameters,
        );

        let new_fhe_bool = |ct: Ciphertext| FheBool {
            ct,
            server_key: shortint_sk,
        };
        let mut result_bool = FheBool::encrypt_trivial(true, shortint_sk);

        let is_lt = |a: &RadixCiphertext, b: &RadixCiphertext| -> FheBool {
            new_fhe_bool(sk.lt_parallelized(a, b).into_inner())
        };

        let is_eq = |a: &RadixCiphertext, b: &RadixCiphertext| -> FheBool {
            new_fhe_bool(sk.eq_parallelized(a, b).into_inner())
        };

        if query.is_empty() {
            // if the query is empty then return true
            return FheBool::encrypt_trivial(true, shortint_sk);
        }

        // else, loop through all atoms
        for (index, (is_node, left, which_op, right, negate)) in query.iter().enumerate() {
            let (is_node, which_op, negate) = (
                new_fhe_bool(is_node.clone()),
                new_fhe_bool(which_op.clone()),
                new_fhe_bool(negate.clone()),
            );

            let val_left = entry_lut.apply(left);
            let val_right = right;
            // (val_left <= val_right) <=> is_lt XOR is_eq
            let is_lt = is_lt(&val_left, val_right);
            let is_eq = is_eq(&val_left, val_right);
            let atom_bool = is_eq + &which_op * is_lt;

            let node_left = query_lut.apply(left, shortint_sk);
            let node_right = query_lut.apply(&sk.cast_to_unsigned(right.clone(), 4), shortint_sk);
            let node_bool = (node_left + &which_op) * (node_right + &which_op) + which_op;

            result_bool = &atom_bool + is_node * (node_bool + &atom_bool) + negate;

            query_lut.update(index as u8, &result_bool);
        }
        result_bool
    }

    /// Runs an encrypted SQL query on a clear table.
    ///
    /// For each table entry, computes (in parallel) if it is present in the
    /// result, ignoring the optional `DISTINCT` flag. Then process the result
    /// to comply with that flag.
    pub fn run_query(&'a self, query: &'a EncryptedQuery) -> EncryptedResult {
        let projection = query
            .projection
            .clone()
            .into_iter()
            .map(|b| b.ct)
            .collect::<Vec<_>>();

        let tmp_result: Vec<FheBool> = self
            .content
            .par_iter()
            .map(|entry| self.run_query_on_entry(entry, &query.where_condition))
            .collect();

        println!("complying with DISTINCT...");
        let bool_result = self
            .comply_with_distinct_bool(&query.distinct, &query.projection, tmp_result.as_slice())
            .into_iter()
            .map(|b| b.ct)
            .collect::<Vec<_>>();
        println!("...DONE.");

        println!("creating trivial encryptions...");
        let content = self
            .content
            .iter()
            .map(|entry| {
                entry
                    .par_iter()
                    .map(|cell| self.server_key.create_trivial_radix(*cell, 32))
                    .collect()
            })
            .collect();
        println!("...done.");

        EncryptedResult {
            is_entry_in_result: bool_result,
            projection,
            content,
            server_key: self.server_key,
            shortint_server_key: self.shortint_server_key,
        }
    }
}

/// A collection of [`TableQueryRunner`]s. The `server_key` attribute is used to
/// combine the various table results inside the method
/// [`DbQueryRunner::run_query`].
pub struct DbQueryRunner<'a> {
    pub server_key: &'a ServerKey,
    pub tables: Vec<TableQueryRunner<'a>>,
}

impl<'a> DbQueryRunner<'a> {
    pub fn new(
        db: Database,
        server_key: &'a ServerKey,
        shortint_server_key: &'a tfhe::shortint::ServerKey,
        wopbs_key: &'a WopbsKey,
        wopbs_parameters: WopbsParameters,
    ) -> Self {
        Self {
            server_key,
            tables: db
                .tables
                .iter()
                .map(|(_, t)| {
                    TableQueryRunner::new(
                        t.clone(),
                        server_key,
                        shortint_server_key,
                        wopbs_key,
                        wopbs_parameters,
                    )
                })
                .collect(),
        }
    }

    /// Returns the width of the encrypted table obtained after calling
    /// [`Self::run_query`].
    ///
    /// It's just the maximum width of each table.
    pub fn output_width(&self) -> u8 {
        self.tables
            .iter()
            .map(|t| t.content[0].len() as u8)
            .fold(0, |a, b| a.max(b))
    }

    /// Returns the length of the encrypted table obtained after calling
    /// [`Self::run_query`].
    ///
    /// It's just the maximum length of each table.
    pub fn output_length(&self) -> u8 {
        self.tables
            .iter()
            .map(|t| t.content.len() as u8)
            .fold(0, |a, b| a.max(b))
    }

    /// Calls [`run_query`](TableQueryRunner::run_query) with the given `query` on each table,
    /// then multiply each result by `0` of `1` depending on the table, and sum each resulting
    /// `EncryptedResult`.
    ///
    /// # Input
    /// An [`EncryptedQuery`].
    /// # Output
    /// an `EncryptedResult`, encrypting a table of length/width equals to the
    /// max length/width of the tables.
    pub fn run_query(&'a self, query: &'a EncryptedQuery) -> EncryptedResult {
        if self.tables.len() == 1 {
            // avoid multiplying the result by a Ciphertext when unnecessary
            self.tables[0].run_query(query)
        } else {
            // run the query on every table, multiply the encrypted by 0 if it's not
            // the correct table
            let mut result_vec = self
                .tables
                .par_iter()
                .enumerate()
                .map(|(i, table)| {
                    let is_correct_table = self
                        .server_key
                        .scalar_eq_parallelized(&query.table_selection, i as u64)
                        .into_inner();

                    let mut result = table.run_query(query);

                    // multiply by 0 or 1
                    println!("multiplying everything by 0 or 1...");
                    result.block_mul_assign(&is_correct_table);
                    println!("...done.");

                    // resize result so that every result have the same dimensions
                    println!("resizing...");
                    result.resize(self.output_length(), self.output_width());
                    println!("...done.");

                    result
                })
                .collect::<Vec<EncryptedResult>>();

            // then sum each table
            let mut acc: EncryptedResult = result_vec.swap_remove(0);
            println!("combining table results...");
            for table in result_vec {
                acc.add_assign(&table)
            }
            println!("...done.");
            acc
        }
    }
}
