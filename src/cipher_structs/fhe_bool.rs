//! Defines a specialized `FheBool` struct.
//!
//! This is done so that `BitXor` is just addition mod 2. Also the degree checks are removed
//! when performing addition. See [`FheBool::binary_smart_op_optimal_cleaning_strategy`].

use tfhe::shortint::ciphertext::NoiseLevel;
use tfhe::shortint::{Ciphertext, ServerKey as ShortintSK};

use tfhe::integer::{BooleanBlock, RadixCiphertext, RadixClientKey, ServerKey};

use std::ops::{Add, AddAssign, Mul, Not};

/// A struct designed to compute the XOR and NOT gates without doing a PBS.
///
/// It essentially uses that `a ^ b = (a + b) % 2`, where booleans are understood
/// as elements of $`\mathbb{Z}/2\mathbb{Z}`$:
/// ```rust
/// match boolean {
///   true  => 1,
///   false => 0,
/// }
/// ```
///
/// Needs a `shortint` server key for computations.
#[derive(Clone)]
pub struct FheBool<'a> {
    pub ct: Ciphertext,
    pub server_key: &'a ShortintSK,
}

impl<'a> FheBool<'a> {
    /// Encrypts a boolean with the given client key.
    pub fn encrypt(val: bool, client_key: &'a RadixClientKey, server_key: &'a ShortintSK) -> Self {
        Self {
            ct: client_key.encrypt_bool(val).into_inner(),
            server_key,
        }
    }

    /// Trivially encrypts a boolean.
    pub fn encrypt_trivial(val: bool, server_key: &'a ShortintSK) -> Self {
        Self {
            ct: server_key.create_trivial(val as u64),
            server_key,
        }
    }

    /// A `FheBool` may not be an encryption of `0` or `1`. This method mutates
    /// such a `FheBool` by taking its residue mod 2.
    pub fn make_boolean(&mut self) {
        self.server_key
            .unchecked_scalar_bitand_assign(&mut self.ct, 1_u8)
    }

    pub fn into_radix(mut self, num_blocks: usize, sks: &ServerKey) -> RadixCiphertext {
        self.make_boolean();
        BooleanBlock::new_unchecked(self.ct).into_radix(num_blocks, sks)
    }

    /// Before doing an operations on 2 inputs which validity is described by
    /// `is_operation_possible`, one or both the inputs may need to be cleaned
    /// (noise reinitilization) with a PBS.
    /// Among possible cleanings this functions returns one of the ones that has
    /// the lowest number of PBS.
    ///
    /// This is copy-pasted from
    /// `tfhe::shortint::server_key::mod::binary_smart_op_optimal_cleaning_strategy`,
    /// and modified to remove handling carries.
    pub fn binary_smart_op_optimal_cleaning_strategy(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        is_operation_possible: impl Fn(&ShortintSK, NoiseLevel, NoiseLevel) -> bool + Copy,
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

                        if is_operation_possible(self.server_key, left_noise, right_noise) {
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
            server_key: self.server_key,
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
/// Copy/pasted from `tfhe::shortint::server_key::add.rs`. Modifies the checks
/// to remove those about the carry bits: uses the custom method
/// [`FheBool::binary_smart_op_optimal_cleaning_strategy`].
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
            let mut bootstrapped_other = other.ct.clone();
            self.server_key
                .message_extract_assign(&mut bootstrapped_other);

            self.server_key
                .unchecked_add_assign(&mut self.ct, &bootstrapped_other);
        } else {
            self.server_key
                .unchecked_add_assign(&mut self.ct, &other.ct);
        }
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
impl<'a, 'b> Add<FheBool<'a>> for &'b FheBool<'a> {
    type Output = FheBool<'a>;
    fn add(self, other: FheBool<'a>) -> FheBool<'a> {
        let mut result = self.clone();
        result += &other;
        result
    }
}

/// Used to XOR two booleans without doing a PBS.
///
/// Redirects to the `AddAssign` implementation.
impl<'a, 'c> Add<&'c FheBool<'a>> for FheBool<'a> {
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

/// Multiplies `&FheBool` with `FheBool`.
///
/// Redirects to the `&FheBool` implementation.
impl<'a, 'b> Mul<FheBool<'a>> for &'b FheBool<'a> {
    type Output = FheBool<'a>;
    fn mul(self, other: FheBool<'a>) -> FheBool<'a> {
        self * &other
    }
}

/// Multiplies `FheBool` with `&FheBool`.
///
/// Redirects to the `&FheBool` implementation.
impl<'a, 'c> Mul<&'c FheBool<'a>> for FheBool<'a> {
    type Output = FheBool<'a>;
    fn mul(self, other: &'c FheBool<'a>) -> FheBool<'a> {
        &self * other
    }
}

/// Multiplies two `FheBool`.
///
/// Redirects to the `&FheBool` implementation.
impl<'a> Mul<FheBool<'a>> for FheBool<'a> {
    type Output = FheBool<'a>;
    fn mul(self, other: FheBool<'a>) -> FheBool<'a> {
        &self * &other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keys;

    #[test]
    fn add_two_fhe_bool() {
        let (ck, _, inner_sk, _, _, _) = generate_keys();
        let b1 = FheBool::encrypt(true, &ck, &inner_sk);
        let b2 = FheBool::encrypt(true, &ck, &inner_sk);

        let xor = b1 + b2;
        let clear_xor = (ck.decrypt_one_block(&xor.ct) % 2) != 0;
        assert_eq!(clear_xor, false);
    }

    #[test]
    fn mul_two_fhe_bool() {
        let (ck, _, inner_sk, _, _, _) = generate_keys();
        let b1 = FheBool::encrypt(true, &ck, &inner_sk);
        let b2 = FheBool::encrypt(true, &ck, &inner_sk);

        let and = b1 * b2;
        let clear_and = (ck.decrypt_one_block(&and.ct) % 2) != 0;
        assert_eq!(clear_and, false);
    }

    #[test]
    fn mix_two_fhe_bool() {
        let (ck, _, inner_sk, _, _, _) = generate_keys();
        let b1 = FheBool::encrypt(true, &ck, &inner_sk);
        let b2 = FheBool::encrypt(true, &ck, &inner_sk);

        let xor = &b1 + &b2;
        let result = b1 * xor;
        let clear_result = (ck.decrypt_one_block(&result.ct) % 2) != 0;
        assert_eq!(clear_result, false);
    }
}
