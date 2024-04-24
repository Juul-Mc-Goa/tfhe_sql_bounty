use crate::{cipher_structs::FheBool, tables::TableQueryRunner};

impl<'a> TableQueryRunner<'a> {
    fn sum_same_projection(
        &'a self,
        index: u8,
        projection: Vec<bool>,
        result: &[FheBool<'a>],
    ) -> FheBool<'a> {
        let index = index as usize;
        self.content
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry
                    .iter()
                    .enumerate()
                    // projection[j] = true => cell = content[index][j]
                    .all(|(j, cell)| !projection[j] || *cell == self.content[index][j])
            })
            .map(|(i, _)| &result[i])
            .fold(
                FheBool::encrypt_trivial(false, &self.shortint_server_key),
                move |a, b| &a + b,
            )
    }

    fn recursive_cmux_distinct(
        &'a self,
        index: u8,
        distinct: &'a FheBool<'a>,
        clear_projection: Vec<bool>,
        projection: &[FheBool<'a>],
        result: &[FheBool<'a>],
    ) -> FheBool<'a> {
        if projection.is_empty() {
            let sum_entries_with_same_proj =
                self.sum_same_projection(index, clear_projection, result);
            &sum_entries_with_same_proj * distinct
        } else {
            let mut first_proj = clear_projection.clone();
            first_proj.push(false);
            let false_case =
                self.recursive_cmux_distinct(index, distinct, first_proj, &projection[1..], result);

            let mut second_proj = clear_projection;
            second_proj.push(true);
            let true_case = self.recursive_cmux_distinct(
                index,
                distinct,
                second_proj,
                &projection[1..],
                result,
            );
            // cmux(projection[0], true_case, false_case)
            &false_case + &(&projection[0] * &(&true_case + &false_case))
        }
    }

    pub fn is_entry_already_in_result(
        &'a self,
        index: u8,
        distinct: &'a FheBool<'a>,
        projection: &[FheBool<'a>],
        result: &[FheBool<'a>],
    ) -> FheBool<'a> {
        self.recursive_cmux_distinct(index, distinct, Vec::new(), projection, result)
    }

    pub fn comply_with_distinct_bool(
        &'a self,
        distinct: &'a FheBool<'a>,
        projection: &[FheBool<'a>],
        result: &[FheBool<'a>],
    ) -> Vec<FheBool<'a>> {
        let n = result.len();
        let mut compliant_result =
            vec![FheBool::encrypt_trivial(false, &self.shortint_server_key); n];

        for (i, result_bool) in result.iter().enumerate() {
            compliant_result[i] = result_bool.clone();

            let is_already_in_result =
                self.is_entry_already_in_result(i as u8, distinct, projection, &compliant_result);

            compliant_result[i] = &compliant_result[i] * &!is_already_in_result;
        }

        compliant_result
    }
}
