use tfhe::shortint::Ciphertext;

use tfhe::integer::wopbs::{IntegerWopbsLUT, WopbsKey};
use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext, ServerKey};

use crate::cipher_structs::recursive_cmux_tree::keyswitch_to_pbs_params;
use rayon::prelude::*;

/// A lookup table, taking (encrypted) `u8` as input, returning (encrypted) `u32`s.
///
/// Internally, this just stores four `u8 -> u8` lookup tables.
pub struct EntryLUT<'a> {
    lut: (
        IntegerWopbsLUT,
        IntegerWopbsLUT,
        IntegerWopbsLUT,
        IntegerWopbsLUT,
        IntegerWopbsLUT,
        IntegerWopbsLUT,
        IntegerWopbsLUT,
        IntegerWopbsLUT,
    ),
    server_key: &'a ServerKey,
    wopbs_key: &'a WopbsKey,
    inner_wopbs_key: &'a tfhe::shortint::wopbs::WopbsKey,
}

impl<'a> EntryLUT<'a> {
    pub fn new(
        entry: &'a Vec<u64>,
        server_key: &'a ServerKey,
        wopbs_key: &'a WopbsKey,
        inner_wopbs_key: &'a tfhe::shortint::wopbs::WopbsKey,
    ) -> Self {
        let entry_length = entry.len();
        // the server_key.generate_lut_radix() method needs a ciphertext for
        // computing the lut size. We use num_blocks = 4, i.e. we assume the
        // total number of columns in a table is lower than 4^4 = 256.
        let max_argument: RadixCiphertext = server_key.create_trivial_radix(entry_length as u64, 4);
        // convenience closure for looking up an entry's cell content from an encrypted index
        let f = |u: u64| -> u64 {
            let v = u as usize;
            if v < entry_length {
                entry[v] as u64
            } else {
                0
            }
        };
        // the input argument to f will be an u8, the output will be an u32,
        // so we decompose one u32 as four u8
        let f0 = |u: u64| -> u64 { f(u) % 256 }; // lsb
        let f1 = |u: u64| -> u64 { (f(u) >> 8) % 256 };
        let f2 = |u: u64| -> u64 { (f(u) >> 16) % 256 };
        let f3 = |u: u64| -> u64 { (f(u) >> 24) % 256 };
        let f4 = |u: u64| -> u64 { (f(u) >> 32) % 256 };
        let f5 = |u: u64| -> u64 { (f(u) >> 40) % 256 };
        let f6 = |u: u64| -> u64 { (f(u) >> 48) % 256 };
        let f7 = |u: u64| -> u64 { (f(u) >> 56) % 256 }; //msb
        let lut = (
            wopbs_key.generate_lut_radix(&max_argument, f0),
            wopbs_key.generate_lut_radix(&max_argument, f1),
            wopbs_key.generate_lut_radix(&max_argument, f2),
            wopbs_key.generate_lut_radix(&max_argument, f3),
            wopbs_key.generate_lut_radix(&max_argument, f4),
            wopbs_key.generate_lut_radix(&max_argument, f5),
            wopbs_key.generate_lut_radix(&max_argument, f6),
            wopbs_key.generate_lut_radix(&max_argument, f7),
        );

        Self {
            lut,
            server_key,
            inner_wopbs_key,
            wopbs_key,
        }
    }

    pub fn apply(&self, index: &RadixCiphertext) -> RadixCiphertext {
        let ct = self
            .wopbs_key
            .keyswitch_to_wopbs_params(self.server_key, index);

        let ct_res0 = self.wopbs_key.wopbs(&ct, &self.lut.0);
        let ct_res1 = self.wopbs_key.wopbs(&ct, &self.lut.1);
        let ct_res2 = self.wopbs_key.wopbs(&ct, &self.lut.2);
        let ct_res3 = self.wopbs_key.wopbs(&ct, &self.lut.3);
        let ct_res4 = self.wopbs_key.wopbs(&ct, &self.lut.4);
        let ct_res5 = self.wopbs_key.wopbs(&ct, &self.lut.5);
        let ct_res6 = self.wopbs_key.wopbs(&ct, &self.lut.6);
        let ct_res7 = self.wopbs_key.wopbs(&ct, &self.lut.7);

        let mut result: Vec<tfhe::shortint::Ciphertext> = Vec::new();

        let mut extend_result = |ct_result: &RadixCiphertext| {
            result.extend(self.keyswitch_to_pbs_params(ct_result).into_blocks());
        };

        extend_result(&ct_res0);
        extend_result(&ct_res1);
        extend_result(&ct_res2);
        extend_result(&ct_res3);
        extend_result(&ct_res4);
        extend_result(&ct_res5);
        extend_result(&ct_res6);
        extend_result(&ct_res7);

        RadixCiphertext::from_blocks(result)
    }

    pub fn keyswitch_block_to_pbs_params(&self, ct_in: &Ciphertext) -> Ciphertext {
        keyswitch_to_pbs_params(&self.inner_wopbs_key, ct_in)
    }

    pub fn keyswitch_to_pbs_params<'b, T>(&self, ct_in: &'b T) -> T
    where
        T: IntegerCiphertext,
        &'b [tfhe::shortint::Ciphertext]:
            IntoParallelIterator<Item = &'b tfhe::shortint::Ciphertext>,
    {
        let blocks: Vec<_> = ct_in
            .blocks()
            .par_iter()
            .map(|block| self.keyswitch_block_to_pbs_params(block))
            .collect();
        T::from_blocks(blocks)
    }
}
