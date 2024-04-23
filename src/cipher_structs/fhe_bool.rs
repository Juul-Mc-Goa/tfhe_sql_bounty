use tfhe::integer::{RadixCiphertext, RadixClientKey};
use tfhe::shortint::ciphertext::NoiseLevel;
use tfhe::shortint::Ciphertext;
use tfhe::shortint::ServerKey;

use std::ops::{Add, AddAssign, Mul, Not};

/// A struct designed to compute the XOR and NOT gates without doing a PBS.
///
/// It essentially uses that `a ^ b = (a + b) % 2`, where booleans are understood
/// as elements of $\mathbb{Z}/2\mathbb{Z}$:
/// ```rust
/// match boolean {
///   true  => 1,
///   false => 0,
/// }
/// ```
///
/// Uses a `shortint` server key for computations.
#[derive(Clone)]
pub struct FheBool<'a> {
    pub ct: Ciphertext,
    pub server_key: &'a tfhe::shortint::ServerKey,
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
            ct: server_key.create_trivial(val as u64),
            server_key,
        }
    }

    pub fn into_boolean(&mut self) {
        self.server_key
            .unchecked_scalar_bitand_assign(&mut self.ct, 1_u8)
    }

    // pub fn into_boolean_block(self) -> BooleanBlock {
    //     let radix_ct = RadixCiphertext::from_blocks(vec![self.ct]);
    //     BooleanBlock::new_unchecked(
    //         self.server_key
    //             .unchecked_scalar_bitand(&radix_ct, 1_u8)
    //             .into_blocks()[0]
    //             .clone(),
    //     )
    // }

    /// Before doing an operations on 2 inputs which validity is described by
    /// `is_operation_possible`, one or both the inputs may need to be cleaned
    /// (noise reinitilization) with a PBS.
    /// Among possible cleanings this functions returns one of the ones that has the lowest number
    /// of PBS
    ///
    /// This is copy-pasted from
    /// `tfhe::shortint::server_key::mod::binary_smart_op_optimal_cleaning_strategy`,
    /// and modified to remove handling carries.
    pub(crate) fn binary_smart_op_optimal_cleaning_strategy(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        is_operation_possible: impl Fn(&ServerKey, NoiseLevel, NoiseLevel) -> bool + Copy,
    ) -> Option<(bool, bool)> {
        [false, true]
            .into_iter()
            .flat_map(move |bootstrap_left| {
                let left_noise = if bootstrap_left {
                    ct_left.noise_degree_if_bootstrapped().noise_level
                } else {
                    ct_left.noise_degree().noise_level
                };

                [false, true]
                    .into_iter()
                    .filter_map(move |bootstrap_right| {
                        let right_noise = if bootstrap_right {
                            ct_right.noise_degree_if_bootstrapped().noise_level
                        } else {
                            ct_right.noise_degree().noise_level
                        };

                        if is_operation_possible(&self.server_key, left_noise, right_noise) {
                            Some((bootstrap_left, bootstrap_right))
                        } else {
                            None
                        }
                    })
            })
            .min_by_key(|(l, r)| usize::from(*l) + usize::from(*r))
    }
}

/// Implements negation for `&FheBool`.
///
/// Uses that `!a = (a + 1) % 2`.
impl<'a, 'b> Not for &'b FheBool<'a> {
    type Output = FheBool<'a>;
    fn not(self) -> Self::Output {
        FheBool {
            ct: self.server_key.unchecked_scalar_add(&self.ct, 1),
            server_key: &self.server_key,
        }
    }
}

/// Implements negation for `FheBool`.
///
/// Uses that `!a = (a + 1) % 2`.
impl<'a> Not for FheBool<'a> {
    type Output = FheBool<'a>;
    fn not(mut self) -> Self::Output {
        self.server_key.unchecked_scalar_add_assign(&mut self.ct, 1);
        self
    }
}

/// Used to XOR two booleans without doing a PBS.
///
/// Copy/pasted from `tfhe::shortint::server_key::add.rs`. `Ciphertexts` can
/// only be added using the `shortint` API, but we use the `integer` one.
impl<'a, 'b> AddAssign<&'b FheBool<'a>> for FheBool<'a> {
    fn add_assign(&mut self, other: &'b FheBool<'a>) {
        // Only check for noise level because we only care about the residue mod 2
        let (bootstrap_left, bootstrap_right) = self
            .binary_smart_op_optimal_cleaning_strategy(&self.ct, &other.ct, |sk, a, b| {
                sk.max_noise_level.validate(a + b).is_ok()
            })
            .unwrap();

        if bootstrap_left {
            self.server_key.message_extract_assign(&mut self.ct)
        }

        if bootstrap_right {
            // can't mutate other so we clone it
            let mut other_ct = other.ct.clone();
            self.server_key.message_extract_assign(&mut other_ct);

            self.server_key
                .unchecked_add_assign(&mut self.ct, &other_ct);
        }

        self.server_key
            .unchecked_add_assign(&mut self.ct, &other.ct);
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
/// Uses the `shortint::ServerKey::bitand` method.
impl<'a, 'b, 'c> Mul<&'c FheBool<'a>> for &'b FheBool<'a> {
    type Output = FheBool<'a>;
    fn mul(self, other: &'c FheBool<'a>) -> FheBool<'a> {
        FheBool {
            ct: self.server_key.bitand(&self.ct, &other.ct),
            server_key: self.server_key,
        }
    }
}

/// Multiplies two `FheBool`.
///
/// Uses the `shortint::ServerKey::bitand_assign` method.
impl<'a> Mul<FheBool<'a>> for FheBool<'a> {
    type Output = FheBool<'a>;
    fn mul(mut self, other: FheBool<'a>) -> FheBool<'a> {
        self.server_key.bitand_assign(&mut self.ct, &other.ct);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keys;

    #[test]
    fn add_two_fhe_bool() {
        let (ck, sk, _wopbs_key, _wopbs_params) = generate_keys();
        let inner_sk = sk.clone().into_raw_parts();
        let b1 = FheBool::encrypt(true, &ck, &inner_sk);
        let b2 = FheBool::encrypt(true, &ck, &inner_sk);

        let xor = b1 + b2;
        let clear_xor = (ck.decrypt_one_block(&xor.ct) % 2) != 0;
        assert_eq!(clear_xor, false);
    }

    #[test]
    fn mul_two_fhe_bool() {
        let (ck, sk, _wopbs_key, _wopbs_params) = generate_keys();
        let inner_sk = sk.clone().into_raw_parts();
        let b1 = FheBool::encrypt(true, &ck, &inner_sk);
        let b2 = FheBool::encrypt(true, &ck, &inner_sk);

        let and = b1 * b2;
        let clear_and = (ck.decrypt_one_block(&and.ct) % 2) != 0;
        assert_eq!(clear_and, false);
    }

    #[test]
    fn mix_two_fhe_bool() {
        let (ck, sk, _wopbs_key, _wopbs_params) = generate_keys();
        let inner_sk = sk.clone().into_raw_parts();
        let b1 = FheBool::encrypt(true, &ck, &inner_sk);
        let b2 = FheBool::encrypt(true, &ck, &inner_sk);

        let xor = &b1 + &b2;
        let result = b1 * xor;
        let clear_result = (ck.decrypt_one_block(&result.ct) % 2) != 0;
        assert_eq!(clear_result, false);
    }
}
