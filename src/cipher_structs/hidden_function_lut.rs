//! Modifies all the necessary `tfhe::integer::wopbs`, `tfhe::shortint::wopbs`,
//! and `tfhe::core_crypto` functions to allow defining "hidden" lookup tables,
//! that is, homomorphic computation of functions `u8 -> FheBool` rather than
//! homomorphic computation of "clear" functions `u8 -> bool`.
//!
//! Here is the list of the copy-pasted and modified functions:
//! - `WopbsKey::wopbs()` (`integer` API)
//! - `WopbsKey::circuit_bootstrapping_vertical_packing()` (`shortint` API)
//! - `WopbsKey::circuit_bootstrap_with_bits() (`shortint` API)`
//! - `circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized()`
//! - `circuit_bootstrap_boolean_vertical_packing()`
//! - `vertical_packing()`
//! - `cmux_tree_memomry_optimized()`

use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, ReborrowMut, SizeOverflow, StackReq};
use rayon::prelude::*;

use tfhe::core_crypto::algorithms::*;
use tfhe::core_crypto::commons::parameters::*;
use tfhe::core_crypto::commons::traits::*;
use tfhe::core_crypto::entities::*;
use tfhe::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKeyView;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::{
    add_external_product_assign as inner_add_external_product_assign,
    FourierGgswCiphertextListMutView, FourierGgswCiphertextListView,
};
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::{
    // blind_rotate_assign as wop_pbs_blind_rotate_assign,
    circuit_bootstrap_boolean,
    circuit_bootstrap_boolean_scratch,
    circuit_bootstrap_boolean_vertical_packing_scratch,
    cmux_tree_memory_optimized_scratch,
};
use tfhe::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};

use concrete_fft::c64;

use tfhe::shortint::{
    ciphertext::{Degree, NoiseLevel},
    engine::ShortintEngine,
    server_key::ShortintBootstrappingKey,
    wopbs::{WopbsKey, WopbsKeyCreationError},
    Ciphertext, ServerKey, WopbsParameters,
};

use tfhe::integer::{IntegerCiphertext, RadixCiphertext};

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

        // TODO: apply private functional keyswitch
        par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            &self.wopbs_key.cbs_pfpksk.get(0),
            &mut self.lut.get_mut(index),
            &value.ct,
        );
        // self.lut.get_mut(index).as_mut_view().as_mut()[0..ct_size]
        //     .copy_from_slice(value.ct.as_ref());
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

        let output_list = self.circuit_bootstrap_with_bits(
            extracted_bits_blocks,
            LweCiphertextCount(1),
            // LweCiphertextCount(vec_lut.output_ciphertext_count().0),
        );

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

#[allow(clippy::too_many_arguments)]
/// Return the required memory for
/// [`circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized`].
fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement<
    Scalar,
>(
    lwe_list_in_count: LweCiphertextCount,
    lwe_in_size: LweSize,
    bsk_output_lwe_size: LweSize,
    glwe_size: GlweSize,
    fpksk_output_polynomial_size: PolynomialSize,
    level_cbs: DecompositionLevelCount,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_all_of([
        // ggsw_list
        StackReq::try_new_aligned::<c64>(
            lwe_list_in_count.0 * fpksk_output_polynomial_size.0 / 2
                * glwe_size.0
                * glwe_size.0
                * level_cbs.0,
            CACHELINE_ALIGN,
        )?,
        // ggsw_res
        StackReq::try_new_aligned::<Scalar>(
            fpksk_output_polynomial_size.0 * glwe_size.0 * glwe_size.0 * level_cbs.0,
            CACHELINE_ALIGN,
        )?,
        StackReq::try_any_of([
            circuit_bootstrap_boolean_scratch::<Scalar>(
                lwe_in_size,
                bsk_output_lwe_size,
                glwe_size,
                fpksk_output_polynomial_size,
                fft,
            )?,
            fft.forward_scratch()?,
            vertical_packing_scratch::<Scalar>(
                glwe_size,
                fpksk_output_polynomial_size,
                lwe_list_in_count.0,
                fft,
            )?,
        ])?,
    ])
}

fn vertical_packing_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ggsw_list_count: usize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_all_of([
        // cmux_tree_lut_res
        StackReq::try_new_aligned::<Scalar>(polynomial_size.0 * glwe_size.0, CACHELINE_ALIGN)?,
        StackReq::try_any_of([cmux_tree_memory_optimized_scratch::<Scalar>(
            glwe_size,
            polynomial_size,
            ggsw_list_count,
            fft,
        )?])?,
    ])
}

fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized<
    InputCont,
    BskCont,
    PFPKSKCont,
>(
    lwe_list_in: &LweCiphertextList<InputCont>,
    lwe_list_out: &mut LweCiphertextList<&mut [u64]>,
    // big_lut_as_polynomial_list: &PolynomialList<LutCont>,
    hidden_function_lut: GlweCiphertextList<&[u64]>,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    pfpksk_list: &LwePrivateFunctionalPackingKeyswitchKeyList<PFPKSKCont>,
    base_log_cbs: DecompositionBaseLog,
    level_cbs: DecompositionLevelCount,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    InputCont: Container<Element = u64>,
    BskCont: Container<Element = c64>,
    PFPKSKCont: Container<Element = u64>,
{
    circuit_bootstrap_boolean_vertical_packing(
        hidden_function_lut,
        fourier_bsk.as_view(),
        lwe_list_out.as_mut_view(),
        lwe_list_in.as_view(),
        pfpksk_list.as_view(),
        level_cbs,
        base_log_cbs,
        fft,
        stack,
    );
}

fn circuit_bootstrap_boolean_vertical_packing(
    // NOTE: the LUT should fit in one polynomial, as its input is an encrypted u8,
    // and its output is a single ciphertext.
    // big_lut_as_polynomial_list: PolynomialList<&[Scalar]>,
    hidden_function_lut: GlweCiphertextList<&[u64]>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    mut lwe_out: LweCiphertextList<&mut [u64]>,
    lwe_list_in: LweCiphertextList<&[u64]>,
    pfpksk_list: LwePrivateFunctionalPackingKeyswitchKeyList<&[u64]>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) {
    debug_assert!(stack.can_hold(
        circuit_bootstrap_boolean_vertical_packing_scratch::<u64>(
            lwe_list_in.lwe_ciphertext_count(),
            lwe_out.lwe_ciphertext_count(),
            lwe_list_in.lwe_size(),
            PolynomialCount(hidden_function_lut.entity_count()),
            fourier_bsk.output_lwe_dimension().to_lwe_size(),
            fourier_bsk.glwe_size(),
            pfpksk_list.output_polynomial_size(),
            level_cbs,
            fft
        )
        .unwrap()
    ));
    debug_assert!(
        lwe_list_in.lwe_ciphertext_count().0 != 0,
        "Got empty `lwe_list_in`"
    );
    debug_assert!(
        lwe_out.lwe_size().to_lwe_dimension() == fourier_bsk.output_lwe_dimension(),
        "Output LWE ciphertext needs to have an LweDimension of {}, got {}",
        lwe_out.lwe_size().to_lwe_dimension().0,
        fourier_bsk.output_lwe_dimension().0
    );
    debug_assert!(lwe_out.ciphertext_modulus() == lwe_list_in.ciphertext_modulus());
    debug_assert!(lwe_list_in.ciphertext_modulus() == pfpksk_list.ciphertext_modulus());
    debug_assert!(
        pfpksk_list.ciphertext_modulus().is_native_modulus(),
        "This operation currently only supports native moduli"
    );

    let glwe_size = pfpksk_list.output_key_glwe_dimension().to_glwe_size();
    let (mut ggsw_list_data, stack) = stack.make_aligned_with(
        lwe_list_in.lwe_ciphertext_count().0 * pfpksk_list.output_polynomial_size().0 / 2
            * glwe_size.0
            * glwe_size.0
            * level_cbs.0,
        CACHELINE_ALIGN,
        |_| c64::default(),
    );
    let (mut ggsw_res_data, mut stack) = stack.make_aligned_with(
        pfpksk_list.output_polynomial_size().0 * glwe_size.0 * glwe_size.0 * level_cbs.0,
        CACHELINE_ALIGN,
        |_| u64::ZERO,
    );

    let mut ggsw_list = FourierGgswCiphertextListMutView::new(
        &mut ggsw_list_data,
        lwe_list_in.lwe_ciphertext_count().0,
        glwe_size,
        pfpksk_list.output_polynomial_size(),
        base_log_cbs,
        level_cbs,
    );

    let mut ggsw_res = GgswCiphertext::from_container(
        &mut *ggsw_res_data,
        glwe_size,
        pfpksk_list.output_polynomial_size(),
        base_log_cbs,
        pfpksk_list.ciphertext_modulus(),
    );

    for (lwe_in, ggsw) in lwe_list_in
        .iter()
        .zip(ggsw_list.as_mut_view().into_ggsw_iter())
    {
        circuit_bootstrap_boolean(
            fourier_bsk,
            lwe_in,
            ggsw_res.as_mut_view(),
            DeltaLog((u64::BITS - 1) as usize),
            pfpksk_list.as_view(),
            fft,
            stack.rb_mut(),
        );

        ggsw.fill_with_forward_fourier(ggsw_res.as_view(), fft, stack.rb_mut());
    }

    // removed the loop as this function is meant to compute a single ciphertext
    vertical_packing(
        hidden_function_lut,
        lwe_out.get_mut(0),
        ggsw_list.as_view(),
        fft,
        stack.rb_mut(),
    );
}

// NOTE: this is called for every output ciphertext computation: thus the lut
// list handles computation of one output ct.
fn vertical_packing(
    lut: GlweCiphertextList<&[u64]>,
    mut lwe_out: LweCiphertext<&mut [u64]>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) {
    let polynomial_size = ggsw_list.polynomial_size();
    let glwe_size = ggsw_list.glwe_size();
    let glwe_dimension = glwe_size.to_glwe_dimension();
    let ciphertext_modulus = lwe_out.ciphertext_modulus();

    debug_assert!(
        lwe_out.lwe_size().to_lwe_dimension()
            == glwe_dimension.to_equivalent_lwe_dimension(polynomial_size),
        "Output LWE ciphertext needs to have an LweDimension of {:?}, got {:?}",
        glwe_dimension.to_equivalent_lwe_dimension(polynomial_size),
        lwe_out.lwe_size().to_lwe_dimension(),
    );

    // // Get the base 2 logarithm (rounded down) of the number of polynomials in the list i.e. if
    // // there is one polynomial, the number will be 0
    // let log_lut_number: usize =
    //     (u64::BITS - 1 - lut.glwe_ciphertext_count().0.leading_zeros()) as usize;

    // let log_number_of_luts_for_cmux_tree = if log_lut_number > ggsw_list.count() {
    //     // this means that we dont have enough GGSW to perform the CMux tree, we can only do the
    //     // Blind rotation
    //     0
    // } else {
    //     log_lut_number
    // };

    // // split the vec of GGSW in two, the msb GGSW is for the CMux tree and the lsb GGSW is for
    // // the last blind rotation.
    // let (cmux_ggsw, br_ggsw) = ggsw_list.split_at(log_number_of_luts_for_cmux_tree);
    let cmux_ggsw = ggsw_list;

    let (mut cmux_tree_lut_res_data, mut stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, CACHELINE_ALIGN, |_| {
            u64::ZERO
        });

    let mut cmux_tree_lut_res = GlweCiphertext::from_container(
        &mut *cmux_tree_lut_res_data,
        polynomial_size,
        ciphertext_modulus,
    );

    cmux_tree_memory_optimized(
        cmux_tree_lut_res.as_mut_view(),
        lut,
        cmux_ggsw,
        fft,
        stack.rb_mut(),
    );
    // cmux_tree_recursive(
    //     cmux_tree_lut_res.as_mut_view(),
    //     lut,
    //     cmux_ggsw,
    //     fft,
    //     stack.rb_mut(),
    // );

    // wop_pbs_blind_rotate_assign(
    //     cmux_tree_lut_res.as_mut_view(),
    //     br_ggsw,
    //     fft,
    //     stack.rb_mut(),
    // );

    // sample extract of the RLWE of the Vertical packing
    extract_lwe_sample_from_glwe_ciphertext(&cmux_tree_lut_res, &mut lwe_out, MonomialDegree(0));
}

// fn cmux_tree_recursive(
//     mut output_glwe: GlweCiphertext<&mut [u64]>,
//     lut: GlweCiphertextList<&[u64]>,
//     ggsw_list: FourierGgswCiphertextListView<'_>,
//     fft: FftView<'_>,
//     stack: PodStack<'_>,
// ) {
//     let glwe_size = output_glwe.glwe_size();
//     let ciphertext_modulus = output_glwe.ciphertext_modulus();
//     let polynomial_size = ggsw_list.polynomial_size();
//     let nb_layer = ggsw_list.count() + 1;

//     let (mut layers_data, stack) = stack.make_aligned_with(
//         polynomial_size.0 * glwe_size.0 * nb_layer,
//         CACHELINE_ALIGN,
//         |_| u64::ZERO,
//     );
//     let mut layers = GlweCiphertextList::from_container(
//         layers_data.as_mut(),
//         glwe_size,
//         polynomial_size,
//         ciphertext_modulus,
//     );

//     fn recursive_cmux<'a>(
//         lut: &GlweCiphertextList<&[u64]>,
//         layers_glwe: &mut GlweCiphertextList<&mut [u64]>,
//         boolean_list: FourierGgswCiphertextListView<'_>,
//         current_lut_index: usize,
//         current_bit_significance: usize,
//         ciphertext_modulus: CiphertextModulus<u64>,
//         polynomial_size: PolynomialSize,
//         fft: FftView<'a>,
//         mut stack: PodStack<'a>,
//     ) {
//         println!("{current_lut_index}, {current_bit_significance}");
//         let new_bit_significance = if current_bit_significance == 0 {
//             0
//         } else {
//             current_bit_significance - 1
//         };
//         if boolean_list.count() == 0 {
//             layers_glwe
//                 .get_mut(0) // layers_glwe should have only one entity
//                 .as_mut()
//                 .copy_from_slice(lut.get(current_lut_index).as_ref());
//         } else {
//             let mid = 1 << current_bit_significance;
//             let other_lut_index = mid + current_lut_index;

//             let (head, tail) = boolean_list.split_at(1);
//             let head = FourierGgswCiphertext::from_container(
//                 head.data(),
//                 head.glwe_size(),
//                 head.polynomial_size(),
//                 head.decomposition_base_log(),
//                 head.decomposition_level_count(),
//             );

//             // first compute layer[i+1]
//             recursive_cmux(
//                 lut,
//                 &mut layers_glwe.get_sub_mut(1..),
//                 tail,
//                 current_lut_index,
//                 new_bit_significance,
//                 ciphertext_modulus.clone(),
//                 polynomial_size.clone(),
//                 fft,
//                 stack.rb_mut(),
//             );

//             // copy layer[i+1] into layer[i]
//             {
//                 // weird iterator gymnastics because layers_glwe is a mutable reference
//                 let mut current_and_next_iter = layers_glwe.iter_mut();
//                 let mut current = current_and_next_iter.next().unwrap();
//                 let next = current_and_next_iter.next().unwrap();
//                 drop(current_and_next_iter);
//                 current.as_mut().copy_from_slice(next.as_ref());
//             }

//             let (diff_data, mut stack) = if other_lut_index >= lut.entity_count() {
//                 stack.rb_mut().collect_aligned(
//                     CACHELINE_ALIGN,
//                     layers_glwe
//                         .get(0)
//                         .as_ref()
//                         .iter()
//                         .map(|&a| 0.wrapping_sub(a)),
//                 )
//             } else {
//                 recursive_cmux(
//                     lut,
//                     &mut layers_glwe.get_sub_mut(1..),
//                     tail,
//                     other_lut_index,
//                     new_bit_significance,
//                     ciphertext_modulus.clone(),
//                     polynomial_size.clone(),
//                     fft,
//                     stack.rb_mut(),
//                 );
//                 stack.rb_mut().collect_aligned(
//                     CACHELINE_ALIGN,
//                     layers_glwe
//                         .get(1)
//                         .as_ref()
//                         .iter()
//                         .zip(layers_glwe.get(0).as_ref().iter())
//                         .map(|(&n, &c)| n.wrapping_sub(c)),
//                 )
//             };

//             let diff =
//                 GlweCiphertext::from_container(&*diff_data, polynomial_size, ciphertext_modulus);

//             inner_add_external_product_assign(
//                 layers_glwe.get_mut(0),
//                 head,
//                 diff,
//                 fft,
//                 stack.rb_mut(),
//             );
//         }
//     }

//     assert_eq!(layers.entity_count(), 1 + ggsw_list.count());
//     println!("depth of cmux tree: {}", ggsw_list.count());

//     recursive_cmux(
//         &lut,
//         &mut layers,
//         ggsw_list,
//         0_usize,
//         ggsw_list.count() - 1,
//         ciphertext_modulus,
//         polynomial_size,
//         fft,
//         stack,
//     );

//     output_glwe.as_mut().copy_from_slice(layers.get(0).as_ref());
// }

fn cmux_tree_memory_optimized(
    mut output_glwe: GlweCiphertext<&mut [u64]>,
    // lut_per_layer: PolynomialList<&[u64]>,
    lut_per_layer: GlweCiphertextList<&[u64]>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) {
    debug_assert!(lut_per_layer.entity_count() == 1 << ggsw_list.count());

    if ggsw_list.count() > 0 {
        let glwe_size = output_glwe.glwe_size();
        let ciphertext_modulus = output_glwe.ciphertext_modulus();
        let polynomial_size = ggsw_list.polynomial_size();
        let nb_layer = ggsw_list.count();

        debug_assert!(stack.can_hold(
            cmux_tree_memory_optimized_scratch::<u64>(glwe_size, polynomial_size, nb_layer, fft)
                .unwrap()
        ));

        // These are accumulator that will be used to propagate the result from layer to layer
        // At index 0 you have the lut that will be loaded, and then the result for each layer gets
        // computed at the next index, last layer result gets stored in `result`.
        // This allow to use memory space in C * nb_layer instead of C' * 2 ^ nb_layer
        let (mut t_0_data, stack) = stack.make_aligned_with(
            polynomial_size.0 * glwe_size.0 * nb_layer,
            CACHELINE_ALIGN,
            |_| u64::ZERO,
        );
        let (mut t_1_data, stack) = stack.make_aligned_with(
            polynomial_size.0 * glwe_size.0 * nb_layer,
            CACHELINE_ALIGN,
            |_| u64::ZERO,
        );

        let mut t_0 = GlweCiphertextList::from_container(
            t_0_data.as_mut(),
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        );
        let mut t_1 = GlweCiphertextList::from_container(
            t_1_data.as_mut(),
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        );

        let (mut t_fill, mut stack) = stack.make_with(nb_layer, |_| 0_usize);

        let mut lut_polynomial_iter = lut_per_layer.iter();

        loop {
            let even = lut_polynomial_iter.next();
            let odd = lut_polynomial_iter.next();

            let (Some(lut_2i), Some(lut_2i_plus_1)) = (even, odd) else {
                break;
            };

            let mut t_iter = t_0.iter_mut().zip(t_1.iter_mut()).enumerate();
            let (mut j_counter, (mut t0_j, mut t1_j)) = t_iter.next().unwrap();

            t0_j.as_mut().copy_from_slice(lut_2i.as_ref());
            // t0_j.get_mut_body()
            //     .as_mut()
            //     .copy_from_slice(lut_2i.as_ref());

            t1_j.as_mut().copy_from_slice(lut_2i_plus_1.as_ref());
            // t1_j.get_mut_body()
            //     .as_mut()
            //     .copy_from_slice(lut_2i_plus_1.as_ref());

            t_fill[0] = 2;

            // iterate from lsb to msb (hence the call to rev())
            for (j, ggsw) in ggsw_list.into_ggsw_iter().rev().enumerate() {
                if t_fill[j] == 2 {
                    let (diff_data, stack) = stack.rb_mut().collect_aligned(
                        CACHELINE_ALIGN,
                        t1_j.as_ref()
                            .iter()
                            .zip(t0_j.as_ref().iter())
                            .map(|(&a, &b)| a.wrapping_sub(b)),
                    );
                    let diff = GlweCiphertext::from_container(
                        &*diff_data,
                        polynomial_size,
                        ciphertext_modulus,
                    );

                    if j < nb_layer - 1 {
                        let (j_counter_plus_1, (mut t_0_j_plus_1, mut t_1_j_plus_1)) =
                            t_iter.next().unwrap();

                        assert_eq!(j_counter, j);
                        assert_eq!(j_counter_plus_1, j + 1);

                        let mut output = if t_fill[j + 1] == 0 {
                            t_0_j_plus_1.as_mut_view()
                        } else {
                            t_1_j_plus_1.as_mut_view()
                        };

                        output.as_mut().copy_from_slice(t0_j.as_ref());
                        inner_add_external_product_assign(output, ggsw, diff, fft, stack);
                        t_fill[j + 1] += 1;
                        t_fill[j] = 0;

                        drop(diff_data);

                        (j_counter, t0_j, t1_j) = (j_counter_plus_1, t_0_j_plus_1, t_1_j_plus_1);
                    } else {
                        assert_eq!(j, nb_layer - 1);
                        let mut output = output_glwe.as_mut_view();
                        output.as_mut().copy_from_slice(t0_j.as_ref());
                        inner_add_external_product_assign(output, ggsw, diff, fft, stack);
                    }
                } else {
                    break;
                }
            }
        }
    } else {
        output_glwe.get_mut_mask().as_mut().fill(u64::ZERO);
        output_glwe.as_mut().copy_from_slice(lut_per_layer.as_ref());
    }
}
