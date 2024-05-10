//! Defines structs for running the encrypted query homomorphically.
//!
//! The bulk of the work is done inside the
//! [`TableQueryRunner::run_query_on_record`] method.
use rayon::prelude::*;
use tfhe::core_crypto::commons::traits::ContiguousEntityContainerMut;
use tfhe::integer::wopbs::WopbsKey;
use tfhe::integer::{RadixCiphertext, ServerKey};
use tfhe::shortint::wopbs::WopbsKey as ShortintWopbsKey;
use tfhe::shortint::{Ciphertext, ServerKey as ShortintSK, WopbsParameters};

use crate::cipher_structs::{query_lut::update_glwe_with_fhe_bool, FheBool, QueryLUT, RecordLUT};
use crate::{Database, Table, TableHeaders};
use crate::{EncryptedQuery, EncryptedSyntaxTree};

/// Holds the result of a SQL query.
///
/// This is not the final result: as it holds references to `ServerKey`s, it
/// cannot be used inside the function `run_fhe_query` (the lifetime logic does
/// not allow it).  The [`EncryptedResult`] struct is defined for that purpose,
/// and removes all references so `ServerKey`s.
pub struct TempEncryptedResult<'a> {
    /// Contains one encrypted boolean for each record.
    pub is_record_in_result: Vec<Ciphertext>,
    /// Contains one encrypted boolean for each column.
    pub projection: Vec<Ciphertext>,
    /// Contains one encrypted `u64` for each cell.
    pub content: Vec<Vec<RadixCiphertext>>,
    /// The server key used for computing over `RadixCipherText`s.
    pub server_key: &'a ServerKey,
    /// The server key used for computing over `CipherText`s.
    pub shortint_server_key: &'a ShortintSK,
}

/// Holds the final result of a SQL query.
pub struct EncryptedResult {
    /// Contains one encrypted boolean for each record.
    pub is_record_in_result: Vec<Ciphertext>,
    /// Contains one encrypted boolean for each column.
    pub projection: Vec<Ciphertext>,
    /// Contains one encrypted `u64` for each cell.
    pub content: Vec<Vec<RadixCiphertext>>,
}

impl From<TempEncryptedResult<'_>> for EncryptedResult {
    fn from(result: TempEncryptedResult) -> Self {
        let TempEncryptedResult {
            is_record_in_result,
            projection,
            content,
            ..
        } = result;

        Self {
            is_record_in_result,
            projection,
            content,
        }
    }
}

impl<'a> TempEncryptedResult<'a> {
    /// Resize an `EncryptedResult` to a given `length` and `width`.
    pub fn resize(&mut self, length: u8, width: u8) {
        let (length, width) = (length as usize, width as usize);
        let value = self.shortint_server_key.create_trivial(0);
        let value_radix: RadixCiphertext = self.server_key.create_trivial_zero_radix(32);

        self.is_record_in_result.resize(length, value.clone());
        self.projection.resize(width, value);

        self.content
            .iter_mut()
            .for_each(|record| record.resize(width, value_radix.clone()));
        self.content.resize(length, vec![value_radix; width]);
    }

    /// Multiply each stored `Ciphertext` or `RadixCiphertext` by a given `Ciphertext`.
    pub fn block_mul_assign(&mut self, ct: &Ciphertext) {
        self.is_record_in_result
            .par_iter_mut()
            .for_each(|record_bool: &mut Ciphertext| {
                self.shortint_server_key.mul_assign(record_bool, ct)
            });
        self.projection
            .par_iter_mut()
            .for_each(|column_bool: &mut Ciphertext| {
                self.shortint_server_key.mul_assign(column_bool, ct)
            });
        self.content.par_iter_mut().for_each(|record| {
            record
                .par_iter_mut()
                .for_each(|cell: &mut RadixCiphertext| {
                    self.server_key.block_mul_assign_parallelized(cell, ct, 0)
                })
        });
    }

    /// Add two `EncryptedResult`s, the result is stored in the first one.
    ///
    /// Used to `XOR` two results.
    pub fn add_assign(&mut self, other: &TempEncryptedResult) {
        assert_eq!(
            self.is_record_in_result.len(),
            other.is_record_in_result.len()
        );
        assert_eq!(self.projection.len(), other.projection.len());

        let add_booleans = |left: &mut Vec<Ciphertext>, right: &[Ciphertext]| {
            for (self_bool, other_bool) in left.iter_mut().zip(right.iter()) {
                self.shortint_server_key.add_assign(self_bool, other_bool)
            }
        };

        add_booleans(&mut self.is_record_in_result, &other.is_record_in_result);
        add_booleans(&mut self.projection, &other.projection);

        self.content
            .par_iter_mut()
            .zip(other.content.par_iter())
            .for_each(|(self_record, other_record)| {
                self_record
                    .par_iter_mut()
                    .zip(other_record.par_iter())
                    .for_each(|(self_cell, other_cell)| {
                        self.server_key
                            .add_assign_parallelized(self_cell, other_cell)
                    })
            });
    }
}

/// An encoded representation of a SQL table, plus a bunch of server keys used
/// during computations.
///
/// Each record is stored as a `Vec<u64>`. A table is a vector of records.
pub struct TableQueryRunner<'a> {
    pub headers: TableHeaders,
    pub content: Vec<Vec<u64>>,
    pub server_key: &'a ServerKey,
    pub shortint_server_key: &'a ShortintSK,
    pub wopbs_key: &'a WopbsKey,
    pub shortint_wopbs_key: &'a ShortintWopbsKey,
    pub wopbs_parameters: WopbsParameters,
}

impl<'a> TableQueryRunner<'a> {
    pub fn new(
        table: Table,
        server_key: &'a ServerKey,
        shortint_server_key: &'a ShortintSK,
        wopbs_key: &'a WopbsKey,
        shortint_wopbs_key: &'a ShortintWopbsKey,
        wopbs_parameters: WopbsParameters,
    ) -> Self {
        Self {
            headers: table.headers.clone(),
            content: table
                .content
                .iter()
                .map(|record| record.iter().flat_map(|cell| cell.encode()).collect())
                .collect::<Vec<Vec<u64>>>(),
            server_key,
            shortint_server_key,
            wopbs_key,
            shortint_wopbs_key,
            wopbs_parameters,
        }
    }

    /// Runs an encrypted query on a given record.
    ///
    /// # Inputs
    /// + `record: &Vec<u64>` an encoded record,
    /// + `query: &EncryptedSyntaxTree` an encrypted `SELECT` query,
    /// + `query_lut: &mut QueryLUT` an updatable, hidden lookup table.
    ///
    /// # Output
    /// + A `Ciphertext` encrypting a boolean that answers the question: "Is
    /// this record selected by the query?"
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
    /// ```math
    /// (a \lt b) \text{ XOR } (a = b) \iff a \leq b
    /// ```
    ///
    /// # Simplification of the boolean formulas:
    ///
    /// The encrypted syntax tree, being a binary tree, has the following property:
    /// + If the tree has `l` leaves, it has `l-1` nodes.
    ///
    /// The `EncryptedSyntaxTree` is a list of `EncryptedInstruction`s, where we assume that:
    /// * the first `l` instructions encode the leaves (ie "atoms"),
    /// * the rest encode the nodes.
    ///
    /// We first write:
    /// ```
    /// node_bool = cmux(
    ///               which_op,
    ///               node_left OR node_right,
    ///               node_left AND node_right) XOR
    ///             negate
    /// atom_bool = cmux(
    ///               which_op,
    ///               val_left <= val_right,
    ///               val_left == val_right) XOR
    ///             negate
    /// ```
    /// and write the formula for a cmux using `+,*`:
    /// ```
    /// cmux(choice, true_case, false_case) = false_case + choice * (true_case + false_case)
    /// ```
    /// using that `2 * false_case = 0` mod 2.
    /// We thus get:
    /// ```
    /// atom_bool = is_eq + which_op * (is_leq + is_eq) + negate
    ///           = is_eq + which_op * is_lt + negate
    /// ```
    /// ```
    /// // see crate-level documentation for how we get this formula
    /// node_bool = (node_left + which_op) * (node_right + which_op) + which_op + negate
    /// ```
    /// Where `is_lt, is_eq, is_leq` are the boolean result of:
    /// 1. `val_left < val_right`
    /// 2. `val_left == val_right`
    /// 3. `val_left <= val_right`
    ///
    /// # Total number of PBS required
    /// * If an atom is computed:
    ///   1. One for retrieving the value associated to an encrypted column identifier,
    ///   2. Two for evaluating `is_eq` and `is_lt`,
    ///   3. One for the `atom_bool` formula,
    /// * If a node is computed:
    ///   1. Two for retrieving `node_left` and `node_right`,
    ///   2. One for the `node_bool` formula.
    ///
    /// Let:
    /// * $`l`$ be the number of atoms in the input query, and
    /// * $`n = 2l - 1`$ be its number of instructions.
    ///
    /// This method performs:
    /// ```math
    /// \begin{split}
    /// 4l + 3(l-1) &= 7l - 3 \\
    ///             &= \frac{7n - 13}{2}
    /// \end{split}
    /// ```
    /// PBS.
    fn run_query_on_record(&'a self, record: &[u64], query: &'a EncryptedSyntaxTree) -> FheBool {
        let sk = self.server_key;
        let shortint_sk = self.shortint_server_key;
        let inner_wopbs = self.shortint_wopbs_key;
        // if an encrypted where condition has n leaves, then it
        // has n-1 nodes: so a total of 2n-1 elements
        let atom_count = (query.len() + 1) / 2;

        let record_lut = RecordLUT::new(record, sk, self.wopbs_key, inner_wopbs);
        let mut query_lut: QueryLUT<'_> =
            QueryLUT::new(query.len(), shortint_sk, inner_wopbs, self.wopbs_parameters);

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

        // if the query is empty then return true
        if query.is_empty() {
            return FheBool::encrypt_trivial(true, shortint_sk);
        }

        // else, loop through all instructions
        // first, split the instruction list into atoms (ie leaves) and nodes
        let (atoms, nodes) = query.split_at(atom_count);

        // atoms can be computed in parallel
        atoms
            .par_iter()
            .zip(query_lut.lut.par_iter_mut())
            .for_each(|(atom, mut lut_value)| {
                let (_, left, which_op, right, negate) = atom;
                let (which_op, negate) =
                    (new_fhe_bool(which_op.clone()), new_fhe_bool(negate.clone()));
                let val_left = record_lut.apply(left);

                let is_lt = is_lt(&val_left, right);
                let is_eq = is_eq(&val_left, right);

                let atom_bool = is_eq + &which_op * is_lt + negate;

                update_glwe_with_fhe_bool(&mut lut_value, &atom_bool, inner_wopbs);
            });

        // if there are no nodes, return the last atom
        if nodes.is_empty() {
            return query_lut.apply(
                &self
                    .server_key
                    .create_trivial_radix::<u64, RadixCiphertext>((atom_count - 1) as u64, 4),
                self.shortint_server_key,
            );
        }

        // else iter through all nodes
        // (nodes have to be computed sequentially)
        for (index, (_, left, which_op, right, negate)) in nodes.iter().enumerate() {
            let index = index + atom_count;
            let (which_op, negate) = (new_fhe_bool(which_op.clone()), new_fhe_bool(negate.clone()));

            let node_left = query_lut.apply(left, shortint_sk);
            let node_right = query_lut.apply(&sk.cast_to_unsigned(right.clone(), 4), shortint_sk);
            result_bool = (node_left + &which_op) * (node_right + &which_op) + which_op + negate;

            query_lut.update(index as u8, &result_bool);
        }

        result_bool
    }

    /// Runs an encrypted SQL query on a clear table.
    ///
    /// For each table record, computes (in parallel) if it is present in the
    /// result, ignoring the optional `DISTINCT` flag. Then process the result
    /// to comply with that flag.
    pub fn run_query(&'a self, query: &'a EncryptedQuery) -> TempEncryptedResult<'a> {
        let projection = query
            .projection
            .clone()
            .into_iter()
            .map(|b| b.ct)
            .collect::<Vec<_>>();

        let tmp_result: Vec<FheBool> = self
            .content
            .par_iter()
            .map(|record| self.run_query_on_record(record, &query.where_condition))
            .collect();

        let bool_result = self
            .comply_with_distinct_bool(&query.distinct, &query.projection, tmp_result.as_slice())
            .into_iter()
            .map(|b| b.ct)
            .collect::<Vec<_>>();

        let content = self
            .content
            .iter()
            .map(|record| {
                record
                    .par_iter()
                    .map(|cell| self.server_key.create_trivial_radix(*cell, 32))
                    .collect()
            })
            .collect();

        TempEncryptedResult {
            is_record_in_result: bool_result,
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
        db: &'a Database,
        server_key: &'a ServerKey,
        shortint_server_key: &'a ShortintSK,
        wopbs_key: &'a WopbsKey,
        shortint_wopbs_key: &'a ShortintWopbsKey,
        wopbs_parameters: WopbsParameters,
    ) -> Self {
        let mut tables: Vec<TableQueryRunner> = Vec::new();

        for (_, t) in &db.tables {
            tables.push(TableQueryRunner::new(
                t.clone(),
                server_key,
                shortint_server_key,
                wopbs_key,
                shortint_wopbs_key,
                wopbs_parameters,
            ));
        }

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
                        shortint_wopbs_key,
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
    /// + `query`: an [`EncryptedQuery`].
    ///
    /// # Output
    /// + an `EncryptedResult`, encrypting a table of length/width equals to the
    /// max length/width of the tables.
    pub fn run_query(&'a self, query: &'a EncryptedQuery) -> EncryptedResult {
        if self.tables.len() == 1 {
            // avoid multiplying the result by a Ciphertext when unnecessary
            self.tables[0].run_query(query).into()
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
                    result.block_mul_assign(&is_correct_table);

                    // resize result so that every result have the same dimensions
                    result.resize(self.output_length(), self.output_width());

                    result
                })
                .collect::<Vec<TempEncryptedResult>>();

            // then sum each table
            let mut acc: TempEncryptedResult = result_vec.swap_remove(0);
            for table in result_vec {
                acc.add_assign(&table)
            }

            acc.into()
        }
    }
}
