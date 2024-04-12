//! Reimplementation of `core_crypto` functions, used for "hidden" lookup tables.
//!
//! Memory requirements reimplementations:
//! - `circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement`
//! - `vertical_packing_scratch`
//! - `cmux_tree_recursive_scratch`
//!
//! Other functions:
//! - `circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized`
//! - `circuit_bootstrap_boolean_vertical_packing`
//! - `vertical_packing`
//! - `cmux_tree_recursive` (replaces `cmux_tree_memory_optimized`)

use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, ReborrowMut, SizeOverflow, StackReq};

use tfhe::core_crypto::algorithms::glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext;
use tfhe::core_crypto::commons::parameters::*;
use tfhe::core_crypto::commons::traits::*;
use tfhe::core_crypto::entities::*;
use tfhe::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKeyView;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::{
    add_external_product_assign as inner_add_external_product_assign,
    add_external_product_assign_scratch, FourierGgswCiphertextListMutView,
    FourierGgswCiphertextListView,
};
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::{
    circuit_bootstrap_boolean, circuit_bootstrap_boolean_scratch,
    circuit_bootstrap_boolean_vertical_packing_scratch,
};
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;

use concrete_fft::c64;

#[allow(clippy::too_many_arguments)]
/// Return the required memory for
/// [`circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized`].
pub fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement<
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

/// Return the required memory for [`vertical_packing`].
pub fn vertical_packing_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ggsw_list_count: usize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_all_of([
        // cmux_tree_lut_res
        StackReq::try_new_aligned::<Scalar>(polynomial_size.0 * glwe_size.0, CACHELINE_ALIGN)?,
        StackReq::try_any_of([cmux_tree_recursive_scratch::<Scalar>(
            glwe_size,
            polynomial_size,
            ggsw_list_count,
            fft,
        )?])?,
    ])
}

/// Return the required memory for [`cmux_tree_recursive`].
pub fn cmux_tree_recursive_scratch<Scalar>(
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
    nb_layer: usize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let layers_scratch =
        StackReq::try_new_aligned::<Scalar>(poly_size.0 * glwe_size.0 * nb_layer, CACHELINE_ALIGN)?;

    StackReq::try_all_of([
        layers_scratch, // layers
        layers_scratch, // nb_layer * diff
        add_external_product_assign_scratch::<Scalar>(glwe_size, poly_size, fft)?,
    ])
}

pub fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized<
    InputCont,
    BskCont,
    PFPKSKCont,
>(
    lwe_list_in: &LweCiphertextList<InputCont>,
    lwe_list_out: &mut LweCiphertextList<&mut [u64]>,
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

pub fn circuit_bootstrap_boolean_vertical_packing(
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

pub fn vertical_packing(
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

    cmux_tree_recursive(
        cmux_tree_lut_res.as_mut_view(),
        lut,
        cmux_ggsw,
        fft,
        stack.rb_mut(),
    );

    // sample extract of the RLWE of the Vertical packing
    extract_lwe_sample_from_glwe_ciphertext(&cmux_tree_lut_res, &mut lwe_out, MonomialDegree(0));
}

/// homomorphic computation of a hidden lookup table.
///
/// Argument `ggsw_list` is meant to be a list of encrypted booleans. Performs a
/// blind rotation by some encrypted value `ct` by just computing cmuxes with
/// the binary decomposition of `ct`.
///
/// Uses the following fact:
/// 1. if `lut` is a list of size $2^n$,
/// 2. if $0 \leq k \leq 2^n$ is an integer with MSB binary decomposition `b:
/// [bool; n]`, and we write `lut[b]` for `lut[k]`,
///
/// then we have:
/// ```rust
/// lut[b] = cmux(b[0], lut1[tail], lut0[tail])
/// ```
/// where:
/// - `tail = b[1..]`
/// - `lut0 = lut[..split_index]`
/// - `lut1 = lut[split_index..]`
/// - `split_index` is equal to $2^{n-1}$.
///
/// Thus no call to the primitive `blind_rotate_assign` is done.
pub fn cmux_tree_recursive(
    mut output_glwe: GlweCiphertext<&mut [u64]>,
    lut: GlweCiphertextList<&[u64]>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) {
    let glwe_size = output_glwe.glwe_size();
    let ciphertext_modulus = output_glwe.ciphertext_modulus();
    let polynomial_size = ggsw_list.polynomial_size();
    let nb_layer = ggsw_list.count() + 1;

    let (mut layers_data, stack) = stack.make_aligned_with(
        polynomial_size.0 * glwe_size.0 * nb_layer,
        CACHELINE_ALIGN,
        |_| u64::ZERO,
    );
    let mut layers = GlweCiphertextList::from_container(
        layers_data.as_mut(),
        glwe_size,
        polynomial_size,
        ciphertext_modulus,
    );

    fn recursive_cmux<'a>(
        lut: &GlweCiphertextList<&[u64]>,
        layers_glwe: &mut GlweCiphertextList<&mut [u64]>,
        boolean_list: FourierGgswCiphertextListView<'_>,
        current_lut_index: usize,
        current_bit_significance: usize,
        ciphertext_modulus: CiphertextModulus<u64>,
        polynomial_size: PolynomialSize,
        fft: FftView<'a>,
        mut stack: PodStack<'a>,
    ) {
        let new_bit_significance = current_bit_significance.saturating_sub(1);
        if boolean_list.count() == 0 {
            layers_glwe
                .get_mut(0) // layers_glwe should have only one entity
                .as_mut()
                .copy_from_slice(lut.get(current_lut_index).as_ref());
        } else {
            let mid = 1 << current_bit_significance;
            let other_lut_index = mid + current_lut_index;

            let (head, tail) = boolean_list.split_at(1);
            // let head = head.to
            let head = FourierGgswCiphertext::from_container(
                head.data(),
                head.glwe_size(),
                head.polynomial_size(),
                head.decomposition_base_log(),
                head.decomposition_level_count(),
            );

            // first compute lut0[tail], result gets stored in layers_glwe[1]
            recursive_cmux(
                lut,
                &mut layers_glwe.get_sub_mut(1..),
                tail,
                current_lut_index,
                new_bit_significance,
                ciphertext_modulus.clone(),
                polynomial_size.clone(),
                fft,
                stack.rb_mut(),
            );

            // copy lut0[tail] into layers_glwe[0]
            {
                // weird iterator gymnastics because layers_glwe is a mutable reference
                let mut current_and_next_iter = layers_glwe.iter_mut();
                let mut current = current_and_next_iter.next().unwrap();
                let next = current_and_next_iter.next().unwrap();
                drop(current_and_next_iter);
                current.as_mut().copy_from_slice(next.as_ref());
            }

            // define diff for the cmux
            let (diff_data, mut stack) = if other_lut_index >= lut.entity_count() {
                // the other index is too large for the lut, so we return the
                // default null glwe
                stack.rb_mut().collect_aligned(
                    CACHELINE_ALIGN,
                    layers_glwe
                        .get(0)
                        .as_ref()
                        .iter()
                        .map(|&a| 0.wrapping_sub(a)),
                )
            } else {
                // compute lut1[tail]
                recursive_cmux(
                    lut,
                    &mut layers_glwe.get_sub_mut(1..),
                    tail,
                    other_lut_index,
                    new_bit_significance,
                    ciphertext_modulus.clone(),
                    polynomial_size.clone(),
                    fft,
                    stack.rb_mut(),
                );
                // compute the difference lut1[tail] - lut0[tail]
                stack.rb_mut().collect_aligned(
                    CACHELINE_ALIGN,
                    layers_glwe
                        .get(1)
                        .as_ref()
                        .iter()
                        .zip(layers_glwe.get(0).as_ref().iter())
                        .map(|(&n, &c)| n.wrapping_sub(c)),
                )
            };

            let diff =
                GlweCiphertext::from_container(&*diff_data, polynomial_size, ciphertext_modulus);

            // compute cmux(head, lut1[tail], lut0[tail])
            inner_add_external_product_assign(
                layers_glwe.get_mut(0), // lut0[tail]
                head,
                diff, // lut1[tail] - lut0[tail]
                fft,
                stack.rb_mut(),
            );
        }
    }

    assert_eq!(layers.entity_count(), 1 + ggsw_list.count());

    recursive_cmux(
        &lut,
        &mut layers,
        ggsw_list,
        0_usize,
        ggsw_list.count() - 1,
        ciphertext_modulus,
        polynomial_size,
        fft,
        stack,
    );

    output_glwe.as_mut().copy_from_slice(layers.get(0).as_ref());
}
