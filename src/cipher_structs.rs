use tfhe::boolean::server_key;
use tfhe::core_crypto::algorithms::{
    lwe_ciphertext_add_assign, lwe_linear_algebra::lwe_ciphertext_plaintext_add_assign,
    lwe_wopbs::circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement,
    lwe_wopbs::extract_bits_from_lwe_ciphertext_mem_optimized,
    lwe_wopbs::extract_bits_from_lwe_ciphertext_mem_optimized_requirement,
};
use tfhe::core_crypto::entities::Plaintext;
use tfhe::core_crypto::fft_impl::fft64::crypto::{
    ggsw::add_external_product_assign, wop_pbs::blind_rotate_assign,
};

use tfhe::shortint::ciphertext::Degree;
use tfhe::shortint::{Ciphertext, WopbsParameters};

use tfhe::integer::wopbs::{encode_radix, IntegerWopbsLUT, WopbsKey, WopbsLUTBase};
use tfhe::integer::{
    BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext, RadixClientKey,
    ServerKey,
};

use std::ops::{Add, AddAssign, Mul, Not};

pub mod hidden_function_lut;

/// A lookup table, taking (encrypted) `u8` as input, returning (encrypted) `u32`s.
pub struct EntryLUT<'a> {
    max_argument: RadixCiphertext,
    lut: (
        IntegerWopbsLUT,
        IntegerWopbsLUT,
        IntegerWopbsLUT,
        IntegerWopbsLUT,
    ),
    server_key: &'a ServerKey,
    wopbs_key: &'a WopbsKey,
    wopbs_parameters: WopbsParameters,
}

impl<'a> EntryLUT<'a> {
    pub fn new(
        entry: &'a Vec<u32>,
        server_key: &'a ServerKey,
        wopbs_key: &'a WopbsKey,
        wopbs_parameters: WopbsParameters,
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
        let f0 = |u: u64| -> u64 { f(u) % 255 }; // lsb
        let f1 = |u: u64| -> u64 { (f(u) >> 8) % 255 };
        let f2 = |u: u64| -> u64 { (f(u) >> 16) % 255 };
        let f3 = |u: u64| -> u64 { (f(u) >> 24) % 255 }; //msb
        let lut = (
            wopbs_key.generate_lut_radix(&max_argument, f0),
            wopbs_key.generate_lut_radix(&max_argument, f1),
            wopbs_key.generate_lut_radix(&max_argument, f2),
            wopbs_key.generate_lut_radix(&max_argument, f3),
        );

        Self {
            max_argument,
            lut,
            server_key,
            wopbs_key,
            wopbs_parameters,
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

        let mut result = self
            .wopbs_key
            .keyswitch_to_pbs_params(&ct_res0)
            .into_blocks();
        result.extend(
            self.wopbs_key
                .keyswitch_to_pbs_params(&ct_res1)
                .into_blocks(),
        );
        result.extend(
            self.wopbs_key
                .keyswitch_to_pbs_params(&ct_res2)
                .into_blocks(),
        );
        result.extend(
            self.wopbs_key
                .keyswitch_to_pbs_params(&ct_res3)
                .into_blocks(),
        );

        RadixCiphertext::from_blocks(result)
    }

    /// Updates a lookup table at the given index.
    ///
    /// This method is mostly a copy-paste of `WopbsKey::generate_lut_radix()`.
    pub fn update(&mut self, index: u8, value: u32) {
        let index = index as usize;
        let value = (
            (value % 255) as u64,
            ((value >> 8) % 255) as u64,
            ((value >> 16) % 255) as u64,
            ((value >> 24) % 255) as u64,
        );

        let basis = self.max_argument.moduli()[0];
        let block_nb = self.max_argument.blocks().len();
        let (wopbs_message_modulus, wopbs_carry_modulus) = (
            self.wopbs_parameters.message_modulus.0,
            self.wopbs_parameters.carry_modulus.0,
        );
        let delta: u64 = (1 << 63) / (wopbs_message_modulus * wopbs_carry_modulus) as u64;
        let mut vec_deg_basis = vec![];

        let mut modulus = 1;
        for (i, deg) in self
            .max_argument
            .moduli()
            .iter()
            .zip(self.max_argument.blocks().iter())
        {
            modulus *= i;
            let b = f64::log2((deg.degree.get() + 1) as f64).ceil() as u64;
            vec_deg_basis.push(b);
        }

        let f_val = (
            value.0 % modulus,
            value.1 % modulus,
            value.2 % modulus,
            value.3 % modulus,
        );
        let encoded_f_val_iter = encode_radix(f_val.0, basis, block_nb as u64)
            .into_iter()
            .zip(encode_radix(f_val.1, basis, block_nb as u64).into_iter())
            .zip(encode_radix(f_val.2, basis, block_nb as u64).into_iter())
            .zip(encode_radix(f_val.3, basis, block_nb as u64).into_iter());
        for (lut_number, radix_encoded_val) in encoded_f_val_iter.enumerate().take(block_nb) {
            let (((v0, v1), v2), v3) = radix_encoded_val;
            self.lut.0[lut_number][index] = v0 * delta;
            self.lut.1[lut_number][index] = v1 * delta;
            self.lut.2[lut_number][index] = v2 * delta;
            self.lut.3[lut_number][index] = v3 * delta;
        }
    }
}

/// A struct designed to compute the XOR and NOT gates without doing a PBS.
///
/// It essentially uses that `a ^ b = (a + b) % 2`, where booleans are understood
/// as elements of Z/2Z:
/// ```rust
/// match boolean {
///   true => 1,
///   false => 0,
/// }
/// ```
#[derive(Clone)]
pub struct FheBool<'a> {
    pub ct: Ciphertext,
    pub server_key: &'a ServerKey,
}

impl<'a> FheBool<'a> {
    pub fn encrypt(val: bool, client_key: &'a RadixClientKey, server_key: &'a ServerKey) -> Self {
        Self {
            ct: client_key.encrypt_bool(val).into_inner(),
            server_key,
        }
    }

    pub fn into_boolean_block(self) -> BooleanBlock {
        let radix_ct = RadixCiphertext::from_blocks(vec![self.ct]);
        BooleanBlock::new_unchecked(
            self.server_key
                .unchecked_scalar_bitand_parallelized(&radix_ct, 1)
                .into_blocks()[0]
                .clone(),
        )
    }
}

/// Implements negation for `&FheBool`.
///
/// Uses that `!a = (a + 1) % 2`.
impl<'a, 'b> Not for &'b FheBool<'a> {
    type Output = FheBool<'a>;
    fn not(self) -> Self::Output {
        let message_modulus = self.server_key.message_modulus().0;
        let carry_modulus = self.server_key.carry_modulus().0;
        let shift_plaintext = (1_u64 << 63) / (message_modulus * carry_modulus) as u64;
        let encoded_scalar = Plaintext(shift_plaintext);

        let mut ct_result = self.ct.clone();
        lwe_ciphertext_plaintext_add_assign(&mut ct_result.ct, encoded_scalar);
        ct_result.degree = Degree::new(ct_result.degree.get() + 1 as usize);

        FheBool {
            ct: ct_result,
            server_key: &self.server_key,
        }
    }
}

/// Implements negation for `FheBool`.
///
/// Uses that `!a = (a + 1) % 2`.
impl<'a> Not for FheBool<'a> {
    type Output = FheBool<'a>;
    fn not(self) -> Self::Output {
        let message_modulus = self.server_key.message_modulus().0;
        let carry_modulus = self.server_key.carry_modulus().0;
        let shift_plaintext = (1_u64 << 63) / (message_modulus * carry_modulus) as u64;
        let encoded_scalar = Plaintext(shift_plaintext);

        let mut ct_result = self.ct;
        lwe_ciphertext_plaintext_add_assign(&mut ct_result.ct, encoded_scalar);
        ct_result.degree = Degree::new(ct_result.degree.get() + 1 as usize);

        FheBool {
            ct: ct_result,
            server_key: &self.server_key,
        }
    }
}

/// Used to XOR two booleans without doing a PBS.
///
/// Copy/pasted from `tfhe::shortint::server_key::add.rs`. `Ciphertexts` can
/// only be added using the `shortint` API, but we use the `integer` one.
impl<'a, 'b> AddAssign<&'b FheBool<'a>> for FheBool<'a> {
    fn add_assign(&mut self, other: &'b FheBool<'a>) {
        lwe_ciphertext_add_assign(&mut self.ct.ct, &other.ct.ct);
        self.ct.degree = Degree::new(self.ct.degree.get() + other.ct.degree.get());
        self.ct
            .set_noise_level(self.ct.noise_level() + other.ct.noise_level());
    }
}

/// Used to XOR two booleans without doing a PBS.
///
/// Redirects to the `AddAssign` implementation.
impl<'a, 'b, 'c> Add<&'c FheBool<'a>> for &'b FheBool<'a> {
    type Output = FheBool<'a>;
    fn add(self, other: &'c FheBool<'a>) -> FheBool<'a> {
        let mut result = self.clone();
        result += other;
        result
    }
}

/// Used to XOR two booleans without doing a PBS.
///
/// Redirects to the `AddAssign` implementation.
impl<'a> Add<FheBool<'a>> for FheBool<'a> {
    type Output = FheBool<'a>;
    fn add(self, other: FheBool<'a>) -> FheBool<'a> {
        let mut result = self.clone();
        result += &other;
        result
    }
}

/// Multiplies two `&FheBool`.
///
/// Uses the `integer::ServerKey::boolean_bitand` method.
impl<'a, 'b, 'c> Mul<&'c FheBool<'a>> for &'b FheBool<'a> {
    type Output = FheBool<'a>;
    fn mul(self, other: &'c FheBool<'a>) -> FheBool<'a> {
        FheBool {
            ct: self
                .server_key
                .boolean_bitand(
                    &BooleanBlock::new_unchecked(self.ct.clone()),
                    &BooleanBlock::new_unchecked(other.ct.clone()),
                )
                .into_inner(),
            server_key: self.server_key,
        }
    }
}

/// Multiplies two `FheBool`.
///
/// Uses the `integer::ServerKey::boolean_bitand` method.
impl<'a> Mul<FheBool<'a>> for FheBool<'a> {
    type Output = FheBool<'a>;
    fn mul(self, other: FheBool<'a>) -> FheBool<'a> {
        FheBool {
            ct: self
                .server_key
                .boolean_bitand(
                    &BooleanBlock::new_unchecked(self.ct),
                    &BooleanBlock::new_unchecked(other.ct),
                )
                .into_inner(),
            server_key: self.server_key,
        }
    }
}

mod tests {
    use super::*;
    use crate::generate_keys;

    #[test]
    fn add_two_fhe_bool() {
        let (ck, sk, _wopbs_key, _wopbs_params) = generate_keys();
        let b1 = FheBool::encrypt(true, &ck, &sk);
        let b2 = FheBool::encrypt(true, &ck, &sk);

        let xor = b1 + b2;
        let clear_xor = ck.decrypt_bool(&xor.into_boolean_block());
        assert_eq!(clear_xor, false);
    }

    #[test]
    fn mul_two_fhe_bool() {
        let (ck, sk, _wopbs_key, _wopbs_params) = generate_keys();
        let b1 = FheBool::encrypt(true, &ck, &sk);
        let b2 = FheBool::encrypt(false, &ck, &sk);

        let and = b1 * b2;
        let clear_and = ck.decrypt_bool(&and.into_boolean_block());
        assert_eq!(clear_and, false);
    }

    #[test]
    fn mix_two_fhe_bool() {
        let (ck, sk, _wopbs_key, _wopbs_params) = generate_keys();
        let b1 = FheBool::encrypt(true, &ck, &sk);
        let b2 = FheBool::encrypt(true, &ck, &sk);

        let xor = &b1 + &b2;
        let result = b1 * xor;
        let clear_result = ck.decrypt_bool(&result.into_boolean_block());
        assert_eq!(clear_result, false);
    }

    // #[test]
    // fn update_lookup_table() {
    //     let (ck, sk, wopbs_key, wopbs_params) = generate_keys();
    //     let entry: Vec<u32> = vec![2, 3, 4, 5, 6];
    //     let mut lut = EntryLUT::new(&entry, &sk, &wopbs_key, wopbs_params);

    //     lut.update(1, 7);

    //     // let lut_at_0 = apply_lut(&ck.as_ref().encrypt_radix(0u64, 4));
    //     let lut_at_1 = lut.apply(&sk.create_trivial_radix(1u64, 4));
    //     let lut_at_2 = lut.apply(&sk.create_trivial_radix(2u64, 4));
    //     let clear1: u32 = ck.decrypt(&lut_at_1);
    //     let clear2: u32 = ck.decrypt(&lut_at_2);

    //     assert_eq!(clear1, 7);
    //     assert_eq!(clear2, 4);
    // }
}
