use tfhe::core_crypto::algorithms::{
    lwe_ciphertext_add_assign, lwe_linear_algebra::lwe_ciphertext_plaintext_add_assign,
};
use tfhe::core_crypto::entities::Plaintext;

use tfhe::integer::{
    BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext, RadixClientKey,
    ServerKey,
};
use tfhe::shortint::ciphertext::Degree;
use tfhe::shortint::Ciphertext;

use std::ops::{Add, Mul, Not};

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

    pub fn encrypt_trivial(val: bool, server_key: &'a ServerKey) -> Self {
        Self {
            ct: server_key.create_trivial_boolean_block(val).into_inner(),
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

#[cfg(test)]
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
