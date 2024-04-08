//! Modifies all the necessary `tfhe::integer::wopbs`, `tfhe::shortint::wopbs`,
//! and `tfhe::core_crypto` functions to allow defining "hidden" lookup tables,
//! that is, homomorphic computation of functions `u8 -> FheBool` rather than
//! homomorphic computation of "clear" functions `u8 -> bool`.
//!
//! Here is the list of the copy-pasted and modified functions:
//! - `WopbsKey::wopbs()` (`integer` API)
//! - `WopbsKey::circuit_bootstrapping_vertical_packing()` (`shortint` API)
//! - `WopbsKey::circuit_bootstrap_with_bits() (`shortint` API)`
//!
//! Two versions of `core_crypto` functions are implemented: one which uses
//! `cmux_tree_memory_optimized` from `core_crypto`, but with a different number
//! of layers, and another which implements its own `cmux_tree_recursive`
//! fonction. The corresponding modules are `regular_cmux_tree` and `recursive_cmux_tree`.
//!
//! Here is the list of modified `core_crypto` functions:
//! - `circuit_bootstrap_boolean_vertical_packing`
//! - `circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized`
//! - `circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement`
//! - `vertical_packing`
//! - `vertical_packing_scratch`
//! - `cmux_tree_memory_optimized`

use rayon::prelude::*;

use tfhe::core_crypto::commons::parameters::*;
use tfhe::core_crypto::commons::traits::*;
use tfhe::core_crypto::entities::*;
use tfhe::core_crypto::fft_impl::fft64::math::fft::Fft;

use tfhe::shortint::{
    ciphertext::{Degree, NoiseLevel},
    engine::ShortintEngine,
    server_key::ShortintBootstrappingKey,
    wopbs::{WopbsKey, WopbsKeyCreationError},
    Ciphertext, ServerKey, WopbsParameters,
};

use tfhe::integer::IntegerCiphertext;

use super::recursive_cmux_tree::*;
// use super::regular_cmux_tree::*;

/// An updatable lookup table, that holds the intermediary `FheBool`s used when
/// running an encrypted SQL query.
pub struct QueryLUT<'a> {
    pub lut: GlweCiphertextList<Vec<u64>>,
    pub server_key: &'a ServerKey,
    pub wopbs_key: &'a WopbsKey, // use shortint API
}

impl<'a> QueryLUT<'a> {
    pub fn new(
        size: usize,
        inner_server_key: &'a ServerKey,
        wopbs_key: &'a WopbsKey,
        wopbs_parameters: WopbsParameters,
    ) -> Self {
        // the server_key.generate_lut_radix() method needs a ciphertext for
        // computing the lut size. We use num_blocks = 4, i.e. we assume the
        // total kength of a queryis lower than 4^4 = 256.
        // let max_argument: RadixCiphertext = integer_server_key.create_trivial_radix(size as u64, 4);

        let lut = GlweCiphertextList::new(
            u64::ZERO,
            wopbs_parameters.glwe_dimension.to_glwe_size(),
            wopbs_key.param.polynomial_size,
            GlweCiphertextCount(size),
            wopbs_parameters.ciphertext_modulus,
        );

        Self {
            lut,
            server_key: inner_server_key,
            wopbs_key,
        }
    }

    pub fn flush(&mut self) {
        self.lut.as_mut().fill(u64::ZERO);
    }

    /// Perform table lookup with argument `index` an encrypted `u8`.
    ///
    /// Returns an encryption of a boolean, of type `Ciphertext`.
    pub fn apply<'b, T>(&self, index: &'b T) -> Ciphertext
    where
        T: IntegerCiphertext,
        &'b [Ciphertext]: IntoParallelIterator<Item = &'b Ciphertext>,
    {
        // copy-paste integer::WopbsKey::keyswitch_to_wopbs_params
        let blocks: Vec<_> = index
            .blocks()
            .par_iter()
            .map(|block| {
                self.wopbs_key
                    .keyswitch_to_wopbs_params(self.server_key, block)
            })
            .collect();
        let ct = T::from_blocks(blocks);
        let ct_res = self.wopbs(&ct);

        self.wopbs_key.keyswitch_to_pbs_params(&ct_res)
    }

    /// Updates a lookup table at the given index.
    pub fn update(&mut self, index: u8, value: Ciphertext) {
        let index = index as usize;

        // keyswitch to wopbs
        let wopbs_value = self
            .wopbs_key
            .keyswitch_to_wopbs_params(self.server_key, &value);

        let mut lut_at_index = self.lut.get_mut(index);
        let (mut mask, mut body) = lut_at_index.get_mut_mask_and_body();

        // manual embedding LWE -> GLWE
        mask.as_mut()
            .copy_from_slice(wopbs_value.ct.get_mask().as_ref());

        // perform the (opposite) steps in extract_lwe_sample_from_glwe_ciphertext in reverse order
        // in this function, the steps are:
        // 1. reverse the mask
        // 2. mutate mask[0..opposite_count] <- - mask[0..opposite_count]
        // 3. rotate the result: mask.rotate_left(opposite_count)
        use tfhe::core_crypto::algorithms::slice_algorithms::slice_wrapping_opposite_assign;
        let opposite_count = mask.as_ref().len() - 1;

        mask.as_mut().rotate_right(opposite_count);
        slice_wrapping_opposite_assign(&mut mask.as_mut()[0..opposite_count]);
        mask.as_mut().reverse();

        // copy the input body into the 0th coefficient of the output body
        body.as_mut()[0] = *wopbs_value.ct.get_body().data;

        // private functional packing with the last pfpksk
        // use tfhe::core_crypto::algorithms::lwe_private_functional_packing_keyswitch::private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext;
        // private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
        //     &self
        //         .wopbs_key
        //         .cbs_pfpksk
        //         .get(self.wopbs_key.cbs_pfpksk.entity_count() - 1),
        //     &mut lut_at_index,
        //     &wopbs_value.ct,
        // );
    }

    /// Inner function called when performing table lookup. Copy-pasted from
    /// `integer::WopbsKey::wopbs`.
    fn wopbs<T>(&self, ct_in: &T) -> Ciphertext
    where
        T: IntegerCiphertext,
    {
        let total_bits_extracted = ct_in.blocks().iter().fold(0usize, |acc, block| {
            acc + f64::log2((block.degree.get() + 1) as f64).ceil() as usize
        });

        let extract_bits_output_lwe_size = self
            .wopbs_key
            .wopbs_server_key
            .key_switching_key
            .output_key_lwe_dimension()
            .to_lwe_size();

        let mut extracted_bits_blocks = LweCiphertextList::new(
            0u64,
            extract_bits_output_lwe_size,
            LweCiphertextCount(total_bits_extracted),
            self.wopbs_key.param.ciphertext_modulus,
        );

        let mut bits_extracted_so_far = 0;

        // Extraction of each bit for each block
        for block in ct_in.blocks().iter().rev() {
            let message_modulus = self.wopbs_key.param.message_modulus.0 as u64;
            let carry_modulus = self.wopbs_key.param.carry_modulus.0 as u64;
            let delta = (1u64 << 63) / (carry_modulus * message_modulus);
            // casting to usize is fine, ilog2 of u64 is guaranteed to be < 64
            let delta_log = DeltaLog(delta.ilog2() as usize);
            let nb_bit_to_extract = f64::log2((block.degree.get() + 1) as f64).ceil() as usize;

            let extract_from_bit = bits_extracted_so_far;
            let extract_to_bit = extract_from_bit + nb_bit_to_extract;
            bits_extracted_so_far += nb_bit_to_extract;

            let mut lwe_sub_list =
                extracted_bits_blocks.get_sub_mut(extract_from_bit..extract_to_bit);

            self.wopbs_key.extract_bits_assign(
                delta_log,
                block,
                ExtractedBitsCount(nb_bit_to_extract),
                &mut lwe_sub_list,
            );
        }

        let vec_ct_out = self.circuit_bootstrapping_vertical_packing(&extracted_bits_blocks);

        let mut ct_vec_out = vec![];
        for (block, block_out) in ct_in.blocks().iter().zip(vec_ct_out) {
            ct_vec_out.push(Ciphertext::new(
                block_out,
                Degree::new(block.message_modulus.0 - 1),
                NoiseLevel::NOMINAL,
                block.message_modulus,
                block.carry_modulus,
                block.pbs_order,
            ));
        }
        ct_vec_out[0].clone()
    }

    fn circuit_bootstrapping_vertical_packing<InputCont>(
        &self,
        extracted_bits_blocks: &LweCiphertextList<InputCont>,
    ) -> Vec<LweCiphertextOwned<u64>>
    where
        InputCont: Container<Element = u64>,
    {
        let output_ciphertext_count = LweCiphertextCount(1);

        let output_list =
            self.circuit_bootstrap_with_bits(extracted_bits_blocks, LweCiphertextCount(1));

        let output_container = output_list.into_container();
        let ciphertext_modulus = self.wopbs_key.param.ciphertext_modulus;
        let lwes: Vec<_> = output_container
            .chunks_exact(output_container.len() / output_ciphertext_count.0)
            .map(|s| LweCiphertextOwned::from_container(s.to_vec(), ciphertext_modulus))
            .collect();

        lwes
    }

    fn circuit_bootstrap_with_bits<InputCont>(
        &self,
        extracted_bits: &LweCiphertextList<InputCont>,
        count: LweCiphertextCount,
    ) -> LweCiphertextListOwned<u64>
    where
        InputCont: Container<Element = u64>,
    {
        let server_key = &self.wopbs_key.wopbs_server_key;
        let fourier_bsk = &server_key.bootstrapping_key;

        let output_lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();

        let mut output_cbs_vp_ct = LweCiphertextListOwned::new(
            0u64,
            output_lwe_size,
            count,
            self.wopbs_key.param.ciphertext_modulus,
        );

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        ShortintEngine::with_thread_local_mut(|engine| {
            let (_, computation_buffers) = engine.get_buffers(server_key);
            computation_buffers.resize(
                circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement::<u64>(
                    extracted_bits.lwe_ciphertext_count(),
                    extracted_bits.lwe_size(),
                    fourier_bsk.output_lwe_dimension().to_lwe_size(),
                    fourier_bsk.glwe_size(),
                    self.wopbs_key.cbs_pfpksk.output_polynomial_size(),
                    self.wopbs_key.param.cbs_level,
                    fft,
                )
                .unwrap()
                .unaligned_bytes_required(),
            );

            let stack = computation_buffers.stack();

            match &server_key.bootstrapping_key {
                ShortintBootstrappingKey::Classic(bsk) => {
                    circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized(
                        extracted_bits,
                        &mut output_cbs_vp_ct.as_mut_view(),
                        GlweCiphertextList::from_container(
                            self.lut.as_ref(),
                            self.lut.glwe_size(),
                            self.lut.polynomial_size(),
                            self.lut.ciphertext_modulus()
                        ),
                        bsk,
                        &self.wopbs_key.cbs_pfpksk,
                        self.wopbs_key.param.cbs_base_log,
                        self.wopbs_key.param.cbs_level,
                        fft,
                        stack,
                    );
                }
                ShortintBootstrappingKey::MultiBit { .. } => {
                    return Err(WopbsKeyCreationError::UnsupportedMultiBit);
                }
            };
            Ok(())
        }).unwrap();

        output_cbs_vp_ct
    }
}
