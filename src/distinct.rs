//! Implements [`TableQueryRunner`] methods for the `DISTINCT` flag.

use crate::{FheBool, TableQueryRunner};

impl<'a> TableQueryRunner<'a> {
    pub fn find_same_projection(&'a self, index: u8, projection: Vec<bool>) -> Vec<u8> {
        let index = index as usize;
        let proj_len = projection.len();
        self.content
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry
                    .iter()
                    .enumerate()
                    // (j < proj_len && projection[j] = true) => cell = content[index][j]
                    .all(|(j, cell)| {
                        j >= proj_len || !projection[j] || *cell == self.content[index][j]
                    })
            })
            .map(|(i, _)| i as u8)
            .collect()
    }

    /// Given:
    /// * `index`: an index
    /// * `projection`: a list of clear booleans encoding which columns are
    /// selected by that query,
    /// * `result`: a list of encrypted booleans encoding which entries are
    /// selected by a `SELECT` query,
    ///
    /// Returns the sum of all encrypted booleans `result[i]` such that for all `j`, we have
    /// `projection[j] = true => self.content[index][j] = self.content[i][j]`.
    fn sum_same_projection(
        &'a self,
        index: u8,
        projection: Vec<bool>,
        result: &[FheBool<'a>],
    ) -> FheBool<'a> {
        self.find_same_projection(index, projection)
            .into_iter()
            .map(|i| &result[i as usize])
            .fold(
                FheBool::encrypt_trivial(false, self.shortint_server_key),
                move |a, b| &a + b,
            )
    }

    /// An internal, recursive method to do what
    /// [`is_entry_already_in_result`](Self::is_entry_already_in_result) needs
    /// to do.
    ///
    /// Simply transforms an encrypted `projection` into a `clear_projection` by
    /// doing a lot of cmuxes, then calls
    /// [`sum_same_projection`](Self::sum_same_projection) with the clear
    /// projection.
    fn recursive_cmux_distinct(
        &'a self,
        index: u8,
        clear_projection: Vec<bool>,
        projection: &[FheBool<'a>],
        result: &[FheBool<'a>],
    ) -> FheBool<'a> {
        if projection.is_empty() {
            self.sum_same_projection(index, clear_projection, result)
        } else {
            let mut first_proj = clear_projection.clone();
            first_proj.push(false);
            let false_case =
                self.recursive_cmux_distinct(index, first_proj, &projection[1..], result);

            let mut second_proj = clear_projection;
            second_proj.push(true);
            let true_case =
                self.recursive_cmux_distinct(index, second_proj, &projection[1..], result);
            // cmux(projection[0], true_case, false_case)
            &false_case + &projection[0] * (true_case + &false_case)
        }
    }

    /// Given:
    /// * `index`: an index
    /// * `result`: a list of encrypted booleans encoding which entries are
    /// selected by a `SELECT` query,
    /// * `projection`: a list of encrypted booleans encoding which columns are
    /// selected by that query,
    ///
    /// returns a boolean answering the question “does an entry such that
    /// `result[i] = true` have the same projection as the entry at index `index` ?”
    ///
    /// <div class="warning">
    ///
    /// This method assumes the following invariant: let `proj(i)` be the tuple
    /// consisting of all the `self.content[i][j]` such that `projection[j] ==
    /// true`. Then if `proj(i1) == proj(i2)`, we have either `result[i1] = false` or
    /// `result[i2] = false`.
    ///
    /// This enables replacing `OR`s by `XOR`s in the computation of the result
    /// boolean. See [`sum_same_projection`](Self::sum_same_projection), and the
    /// [`crate`](crate#replacing-boolean-operators-with-addition-and-multiplication-mod-2)
    /// docs for why `XOR` is replaced by `+`.
    ///
    /// </div>
    pub fn is_entry_already_in_result(
        &'a self,
        index: u8,
        projection: &[FheBool<'a>],
        result: &[FheBool<'a>],
    ) -> FheBool<'a> {
        self.recursive_cmux_distinct(index, Vec::new(), projection, result)
    }

    /// Given:
    /// * `distinct`: an encrypted boolean,
    /// * `result`: a list of encrypted booleans encoding which entries are
    /// selected by a `SELECT` query,
    /// * `projection`: a list of encrypted booleans encoding which columns are
    /// selected by that query,
    ///
    /// Returns a list en encrypted booleans of the same size as `result`, but in which
    /// duplicates are removed, if `distinct` is true.
    pub fn comply_with_distinct_bool(
        &'a self,
        distinct: &'a FheBool<'a>,
        projection: &[FheBool<'a>],
        result: &[FheBool<'a>],
    ) -> Vec<FheBool<'a>> {
        let n = result.len();
        let mut compliant_result =
            vec![FheBool::encrypt_trivial(false, self.shortint_server_key); n];

        for (i, result_bool) in result.iter().enumerate() {
            let is_in_result =
                self.is_entry_already_in_result(i as u8, projection, &compliant_result);

            // make_false = distinct AND is_in_result
            let make_false = distinct * &is_in_result;

            compliant_result[i] = result_bool * &!make_false;
        }

        compliant_result
    }
}
