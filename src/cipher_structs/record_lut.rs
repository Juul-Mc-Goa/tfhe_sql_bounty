//! Defines a lookup table taking (encrypted) `u8` as input, and returning
//! (encrypted) `u64`s.

use tfhe::core_crypto::commons::parameters::*;

use tfhe::integer::wopbs::{decode_radix, encode_mix_radix, encode_radix};
use tfhe::shortint::{wopbs::WopbsKey as InnerWopbsKey, Ciphertext};

use tfhe::integer::wopbs::{IntegerWopbsLUT, WopbsKey};
use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext, ServerKey};

use crate::cipher_structs::recursive_cmux_tree::keyswitch_to_pbs_params;
use rayon::prelude::*;

/// A lookup table, taking (encrypted) `u8` as input, returning (encrypted) `u64`s.
///
/// Internally, this just stores eight `u8 -> u8` lookup tables.
pub struct RecordLUT<'a> {
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

impl<'a> RecordLUT<'a> {
    pub fn new(
        record: &'a [u64],
        server_key: &'a ServerKey,
        wopbs_key: &'a WopbsKey,
        inner_wopbs_key: &'a tfhe::shortint::wopbs::WopbsKey,
    ) -> Self {
        let record_length = record.len();
        // the server_key.generate_lut_radix() method needs a ciphertext for
        // computing the lut size. We use num_blocks = 4, i.e. we assume the
        // total number of columns in a table is lower than 4^4 = 256.
        let max_argument: RadixCiphertext =
            server_key.create_trivial_radix(record_length as u64, 4);
        // convenience closure for looking up an record's cell content from an encrypted index
        let f = |u: u64| -> u64 {
            let v = u as usize;
            if v < record_length {
                record[v]
            } else {
                0
            }
        };
        // the input argument to f will be an u8, the output will be an u64,
        // so we decompose one u64 as eight u8
        let f0 = |u: u64| -> u64 { f(u) % 256 }; // lsb
        let f1 = |u: u64| -> u64 { (f(u) >> 8) % 256 };
        let f2 = |u: u64| -> u64 { (f(u) >> 16) % 256 };
        let f3 = |u: u64| -> u64 { (f(u) >> 24) % 256 };
        let f4 = |u: u64| -> u64 { (f(u) >> 32) % 256 };
        let f5 = |u: u64| -> u64 { (f(u) >> 40) % 256 };
        let f6 = |u: u64| -> u64 { (f(u) >> 48) % 256 };
        let f7 = |u: u64| -> u64 { (f(u) >> 56) % 256 }; //msb
        let lut = (
            Self::generate_lut_radix(&inner_wopbs_key, &max_argument, f0),
            Self::generate_lut_radix(&inner_wopbs_key, &max_argument, f1),
            Self::generate_lut_radix(&inner_wopbs_key, &max_argument, f2),
            Self::generate_lut_radix(&inner_wopbs_key, &max_argument, f3),
            Self::generate_lut_radix(&inner_wopbs_key, &max_argument, f4),
            Self::generate_lut_radix(&inner_wopbs_key, &max_argument, f5),
            Self::generate_lut_radix(&inner_wopbs_key, &max_argument, f6),
            Self::generate_lut_radix(&inner_wopbs_key, &max_argument, f7),
        );

        RecordLUT {
            lut,
            server_key,
            inner_wopbs_key,
            wopbs_key,
        }
    }

    /// Copy-pasted from `tfhe::integer::wopbs`. Fixed the computation of `vec_deg_basis`.
    pub fn generate_lut_radix<F, T>(wopbs_key: &InnerWopbsKey, ct: &T, f: F) -> IntegerWopbsLUT
    where
        F: Fn(u64) -> u64,
        T: IntegerCiphertext,
    {
        let mut total_bit = 0;
        let block_nb = ct.blocks().len();
        let mut modulus = 1;

        //This contains the basis of each block depending on the degree
        let mut vec_deg_basis = vec![];

        for (i, _deg) in ct.moduli().iter().zip(ct.blocks().iter()) {
            modulus *= i;
            let b = f64::log2(*i as f64).ceil() as u64;
            vec_deg_basis.push(b);
            total_bit += b;
        }

        let lut_size = if 1 << total_bit < wopbs_key.param.polynomial_size.0 as u64 {
            wopbs_key.param.polynomial_size.0
        } else {
            1 << total_bit
        };
        let mut lut = IntegerWopbsLUT::new(PlaintextCount(lut_size), CiphertextCount(block_nb));

        let basis = ct.moduli()[0];
        let delta: u64 = (1 << 63)
            / (wopbs_key.param.message_modulus.0 * wopbs_key.param.carry_modulus.0) as u64;

        for lut_index_val in 0..(1 << total_bit) {
            let encoded_with_deg_val = encode_mix_radix(lut_index_val, &vec_deg_basis, basis);
            let decoded_val = decode_radix(&encoded_with_deg_val, basis);
            let f_val = f(decoded_val % modulus) % modulus;
            let encoded_f_val = encode_radix(f_val, basis, block_nb as u64);
            for (lut_number, radix_encoded_val) in encoded_f_val.iter().enumerate().take(block_nb) {
                lut[lut_number][lut_index_val as usize] = radix_encoded_val * delta;
            }
        }
        lut
    }

    pub fn apply(&self, index: &RadixCiphertext) -> RadixCiphertext {
        // let mut safe_index = index.clone();
        // self.server_key.full_propagate(&mut safe_index);

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
            let pbs_result = self.keyswitch_to_pbs_params(ct_result);
            result.extend(pbs_result.into_blocks());
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
        keyswitch_to_pbs_params(self.inner_wopbs_key, ct_in)
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
