//! Modifies all the necessary `tfhe::integer::wopbs`, `tfhe::shortint::wopbs`,
//! and `tfhe::core_crypto` functions to allow defining "hidden" lookup tables,
//! that is, FHE counterparts of functions `u8 -> FheBool` rather than FHE
//! counterparts of "clear" functions `u8 -> bool`.
//!
//! Here is the list of the copy-pasted and modified functions:
//! - `WopbsKey::wopbs()` (`integer` API)
//! - `WopbsKey::circuit_bootstrapping_vertical_packing()` (`shortint` API)
//! - `WopbsKey::circuit_bootstrap_with_bits() (`shortint` API)`
//! - `circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized()`
//! - `circuit_bootstrap_boolean_vertical_packing()`
//! - `circuit_bootstrap_boolean()`
//! - `vertical_packing()`
//! - `cmux_tree_optimized()`

use dyn_stack::PodStack;

use tfhe::core_crypto::{
    algorithms::{
        lwe_ciphertext_add_assign,
        lwe_linear_algebra::lwe_ciphertext_plaintext_add_assign,
        lwe_wopbs::{
            circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement,
            extract_bits_from_lwe_ciphertext_mem_optimized,
            extract_bits_from_lwe_ciphertext_mem_optimized_requirement,
        },
    },
    commons::{
        parameters::{DeltaLog, LweCiphertextCount},
        traits::Container,
    },
    entities::{
        GgswCiphertext, GlweCiphertext, GlweCiphertextList, LweCiphertextList,
        LweCiphertextListOwned, Plaintext, PolynomialList, PolynomialListView,
    },
    fft_impl::fft64::{
        crypto::{
            ggsw::{add_external_product_assign, FourierGgswCiphertext},
            wop_pbs::{blind_rotate_assign, circuit_bootstrap_boolean},
        },
        math::fft::Fft,
    },
};

use tfhe::shortint::{
    ciphertext::{Degree, NoiseLevel},
    server_key::ShortintBootstrappingKey,
    wopbs::{WopbsKeyCreationError, WopbsLUTBase},
    Ciphertext, WopbsParameters,
};

use tfhe::integer::{
    wopbs::{encode_radix, IntegerWopbsLUT, WopbsKey},
    BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext, RadixClientKey,
    ServerKey,
};

/// An updatable lookup table, that holds the intermediary `FheBool`s used when
/// running an encrypted SQL query.
pub struct QueryLUT<'a> {
    max_argument: RadixCiphertext,
    lut: IntegerWopbsLUT,
    server_key: &'a ServerKey,
    wopbs_key: &'a WopbsKey, // TODO: use shortint API
    wopbs_parameters: WopbsParameters,
}

impl<'a> QueryLUT<'a> {
    pub fn new(
        size: usize,
        server_key: &'a ServerKey,
        wopbs_key: &'a WopbsKey,
        wopbs_parameters: WopbsParameters,
    ) -> Self {
        // the server_key.generate_lut_radix() method needs a ciphertext for
        // computing the lut size. We use num_blocks = 4, i.e. we assume the
        // total kength of a queryis lower than 4^4 = 256.
        let max_argument: RadixCiphertext = server_key.create_trivial_radix(size as u64, 4);
        // convenience closure for looking up an entry's cell content from an encrypted index
        let f = |_: u64| -> u64 { 0 };
        let lut = wopbs_key.generate_lut_radix(&max_argument, f);

        Self {
            max_argument,
            lut,
            server_key,
            wopbs_key,
            wopbs_parameters,
        }
    }

    pub fn apply(&self, index: &RadixCiphertext) -> Ciphertext {
        let ct = self
            .wopbs_key
            .keyswitch_to_wopbs_params(self.server_key, index);
        let ct_res = self.wopbs_key.wopbs(&ct, &self.lut);
        self.wopbs_key
            .keyswitch_to_pbs_params(&ct_res)
            .into_blocks()[0]
            .clone()
    }

    /// Updates a lookup table at the given index.
    ///
    /// This method is mostly a copy-paste of `WopbsKey::generate_lut_radix()`.
    pub fn update(&mut self, index: u8, value: bool) {
        let index = index as usize;

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

        let f_val = value as u64;
        let encoded_f_val = encode_radix(f_val, basis, block_nb as u64);
        for (lut_number, radix_encoded_val) in encoded_f_val.iter().enumerate().take(block_nb) {
            self.lut[lut_number][index] = radix_encoded_val * delta;
        }
    }

    fn wopbs<T>(&self, ct_in: &T, lut: &IntegerWopbsLUT) -> T
    where
        T: IntegerCiphertext,
    {
        let total_bits_extracted = ct_in.blocks().iter().fold(0usize, |acc, block| {
            acc + f64::log2((block.degree.get() + 1) as f64).ceil() as usize
        });

        // let extract_bits_output_lwe_size = self
        //     .wopbs_key
        //     .wopbs_server_key
        //     .key_switching_key
        //     .output_key_lwe_dimension()
        //     .to_lwe_size();

        // TODO: do not clone wopbs_key
        let extract_bits_output_lwe_size = self
            .wopbs_key
            .clone()
            .into_raw_parts()
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

        // let vec_ct_out = self
        //     .wopbs_key
        //     .circuit_bootstrapping_vertical_packing(lut.as_ref(), &extracted_bits_blocks);

        let vec_ct_out =
            self.circuit_bootstrapping_vertical_packing(lut.as_ref(), &extracted_bits_blocks);

        let mut ct_vec_out = vec![];
        for (block, block_out) in ct_in.blocks().iter().zip(vec_ct_out) {
            ct_vec_out.push(crate::shortint::Ciphertext::new(
                block_out,
                Degree::new(block.message_modulus.0 - 1),
                NoiseLevel::NOMINAL,
                block.message_modulus,
                block.carry_modulus,
                block.pbs_order,
            ));
        }
        T::from_blocks(ct_vec_out)
    }

    pub fn extract_bits_assign<OutputCont>(
        &self,
        delta_log: DeltaLog,
        ciphertext: &Ciphertext,
        num_bits_to_extract: ExtractedBitsCount,
        output: &mut LweCiphertextList<OutputCont>,
    ) where
        OutputCont: ContainerMut<Element = u64>,
    {
        // TODO: remove the .clone()
        let server_key = &self.wopbs_key.clone().into_raw_parts().wopbs_server_key;

        let bsk = &server_key.bootstrapping_key;
        let ksk = &server_key.key_switching_key;

        let fft = Fft::new(bsk.polynomial_size());
        let fft = fft.as_view();

        ShortintEngine::with_thread_local_mut(|engine| {
            engine.computation_buffers.resize(
                extract_bits_from_lwe_ciphertext_mem_optimized_requirement::<u64>(
                    ciphertext.ct.lwe_size().to_lwe_dimension(),
                    ksk.output_key_lwe_dimension(),
                    bsk.glwe_size(),
                    bsk.polynomial_size(),
                    fft,
                )
                .unwrap()
                .unaligned_bytes_required(),
            );

            let stack = engine.computation_buffers.stack();

            match bsk {
                ShortintBootstrappingKey::Classic(bsk) => {
                    extract_bits_from_lwe_ciphertext_mem_optimized(
                        &ciphertext.ct,
                        output,
                        bsk,
                        ksk,
                        delta_log,
                        num_bits_to_extract,
                        fft,
                        stack,
                    );
                }
                ShortintBootstrappingKey::MultiBit { .. } => {
                    todo!("extract_bits_assign currently does not support multi-bit PBS")
                }
            }
        });
    }

    fn circuit_bootstrapping_vertical_packing<InputCont>(
        &self,
        vec_lut: &WopbsLUTBase,
        extracted_bits_blocks: &LweCiphertextList<InputCont>,
    ) -> Vec<LweCiphertextOwned<u64>>
    where
        InputCont: Container<Element = u64>,
    {
        let output_list = self.circuit_bootstrap_with_bits(
            extracted_bits_blocks,
            &vec_lut.lut(),
            LweCiphertextCount(vec_lut.output_ciphertext_count().0),
        );

        let output_container = output_list.into_container();
        // TODO: use self.wopbs_key
        let ciphertext_modulus = self.wopbs_parameters.ciphertext_modulus;
        let lwes: Vec<_> = output_container
            .chunks_exact(output_container.len() / vec_lut.output_ciphertext_count().0)
            .map(|s| LweCiphertextOwned::from_container(s.to_vec(), ciphertext_modulus))
            .collect();

        lwes
    }

    fn circuit_bootstrap_with_bits<InputCont, LutCont>(
        &self,
        extracted_bits: &LweCiphertextList<InputCont>,
        lut: &PlaintextList<LutCont>,
        count: LweCiphertextCount,
    ) -> LweCiphertextListOwned<u64>
    where
        InputCont: Container<Element = u64>,
        LutCont: Container<Element = u64>,
    {
        // TODO: remove the .clone()
        let server_key = &self.wopbs_key.clone().into_raw_parts().wopbs_server_key;
        let fourier_bsk = &sks.bootstrapping_key;

        let output_lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();

        let mut output_cbs_vp_ct = LweCiphertextListOwned::new(
            0u64,
            output_lwe_size,
            count,
            self.param.ciphertext_modulus,
        );
        // TODO: do not use PolynomialListView
        let lut = PolynomialListView::from_container(lut.as_ref(), fourier_bsk.polynomial_size());

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        ShortintEngine::with_thread_local_mut(|engine| {
            engine.computation_buffers.resize(
                circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement::<u64>(
                    extracted_bits.lwe_ciphertext_count(),
                    output_cbs_vp_ct.lwe_ciphertext_count(),
                    extracted_bits.lwe_size(),
                    lut.polynomial_count(),
                    fourier_bsk.output_lwe_dimension().to_lwe_size(),
                    fourier_bsk.glwe_size(),
                    self.cbs_pfpksk.output_polynomial_size(),
                    self.param.cbs_level,
                    fft,
                )
                .unwrap()
                .unaligned_bytes_required(),
            );

            let stack = engine.computation_buffers.stack();

            match &sks.bootstrapping_key {
                ShortintBootstrappingKey::Classic(bsk) => {
                    circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized(
                        extracted_bits,
                        &mut output_cbs_vp_ct,
                        &lut,
                        bsk,
                        &self.cbs_pfpksk,
                        self.param.cbs_base_log,
                        self.param.cbs_level,
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

// TODO: change big_lut_as_polynomial_list
fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized<
    Scalar,
    InputCont,
    OutputCont,
    LutCont,
    BskCont,
    PFPKSKCont,
>(
    lwe_list_in: &LweCiphertextList<InputCont>,
    lwe_list_out: &mut LweCiphertext,
    big_lut_as_polynomial_list: &PolynomialList<LutCont>,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    pfpksk_list: &LwePrivateFunctionalPackingKeyswitchKeyList<PFPKSKCont>,
    base_log_cbs: DecompositionBaseLog,
    level_cbs: DecompositionLevelCount,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    LutCont: Container<Element = Scalar>,
    BskCont: Container<Element = c64>,
    PFPKSKCont: Container<Element = Scalar>,
{
    circuit_bootstrap_boolean_vertical_packing(
        big_lut_as_polynomial_list.as_view(),
        fourier_bsk.as_view(),
        lwe_list_out,
        lwe_list_in.as_view(),
        pfpksk_list.as_view(),
        level_cbs,
        base_log_cbs,
        fft,
        stack,
    );
}

// TODO: change big_lut_as_polynomial_list
fn circuit_bootstrap_boolean_vertical_packing<Scalar: UnsignedTorus + CastInto<usize>>(
    big_lut_as_polynomial_list: PolynomialList<&[Scalar]>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    mut lwe_out: LweCiphertext,
    lwe_list_in: LweCiphertextList<&[Scalar]>,
    pfpksk_list: LwePrivateFunctionalPackingKeyswitchKeyList<&[Scalar]>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) {
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
        |_| Scalar::ZERO,
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

    for (lwe_in, ggsw) in izip!(lwe_list_in.iter(), ggsw_list.as_mut_view().into_ggsw_iter(),) {
        circuit_bootstrap_boolean(
            fourier_bsk,
            lwe_in,
            ggsw_res.as_mut_view(),
            DeltaLog(Scalar::BITS - 1),
            pfpksk_list.as_view(),
            fft,
            stack.rb_mut(),
        );

        ggsw.fill_with_forward_fourier(ggsw_res.as_view(), fft, stack.rb_mut());
    }

    // We deduce the number of luts in the vec_lut from the number of cipherxtexts in lwe_list_out
    let number_of_luts = 1;

    let small_lut_size = big_lut_as_polynomial_list.polynomial_count().0;

    vertical_packing(lut, lwe_out, ggsw_list.as_view(), fft, stack.rb_mut());
    // for (lut, lwe_out) in izip!(
    //     big_lut_as_polynomial_list.chunks_exact(small_lut_size),
    //     lwe_list_out.iter_mut(),
    // ) {
    //     vertical_packing(lut, lwe_out, ggsw_list.as_view(), fft, stack.rb_mut());
    // }
}

// TODO: do not use PolynomialList
fn vertical_packing<Scalar: UnsignedTorus + CastInto<usize>>(
    lut: PolynomialList<&[Scalar]>,
    mut lwe_out: LweCiphertext<&mut [Scalar]>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) {
    let polynomial_size = ggsw_list.polynomial_size();
    let glwe_size = ggsw_list.glwe_size();
    let glwe_dimension = glwe_size.to_glwe_dimension();
    let ciphertext_modulus = lwe_out.ciphertext_modulus();

    // Get the base 2 logarithm (rounded down) of the number of polynomials in the list i.e. if
    // there is one polynomial, the number will be 0
    let log_lut_number: usize =
        Scalar::BITS - 1 - lut.polynomial_count().0.leading_zeros() as usize;

    let log_number_of_luts_for_cmux_tree = if log_lut_number > ggsw_list.count() {
        // this means that we dont have enough GGSW to perform the CMux tree, we can only do the
        // Blind rotation
        0
    } else {
        log_lut_number
    };

    // split the vec of GGSW in two, the msb GGSW is for the CMux tree and the lsb GGSW is for
    // the last blind rotation.
    let (cmux_ggsw, br_ggsw) = ggsw_list.split_at(log_number_of_luts_for_cmux_tree);

    let (mut cmux_tree_lut_res_data, mut stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, CACHELINE_ALIGN, |_| {
            Scalar::ZERO
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
    blind_rotate_assign(
        cmux_tree_lut_res.as_mut_view(),
        br_ggsw,
        fft,
        stack.rb_mut(),
    );

    // sample extract of the RLWE of the Vertical packing
    extract_lwe_sample_from_glwe_ciphertext(&cmux_tree_lut_res, &mut lwe_out, MonomialDegree(0));
}

// TODO: do not use PolynomialList
fn cmux_tree_memory_optimized<Scalar: UnsignedTorus + CastInto<usize>>(
    mut output_glwe: GlweCiphertext<&mut [Scalar]>,
    lut_per_layer: PolynomialList<&[Scalar]>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) {
    debug_assert!(lut_per_layer.polynomial_count().0 == 1 << ggsw_list.count());

    if ggsw_list.count() > 0 {
        let glwe_size = output_glwe.glwe_size();
        let ciphertext_modulus = output_glwe.ciphertext_modulus();
        let polynomial_size = ggsw_list.polynomial_size();
        let nb_layer = ggsw_list.count();

        // These are accumulator that will be used to propagate the result from layer to layer
        // At index 0 you have the lut that will be loaded, and then the result for each layer gets
        // computed at the next index, last layer result gets stored in `result`.
        // This allow to use memory space in C * nb_layer instead of C' * 2 ^ nb_layer
        let (mut t_0_data, stack) = stack.make_aligned_with(
            polynomial_size.0 * glwe_size.0 * nb_layer,
            CACHELINE_ALIGN,
            |_| Scalar::ZERO,
        );
        let (mut t_1_data, stack) = stack.make_aligned_with(
            polynomial_size.0 * glwe_size.0 * nb_layer,
            CACHELINE_ALIGN,
            |_| Scalar::ZERO,
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

            let mut t_iter = izip!(t_0.iter_mut(), t_1.iter_mut(),).enumerate();

            let (mut j_counter, (mut t0_j, mut t1_j)) = t_iter.next().unwrap();

            t0_j.get_mut_body()
                .as_mut()
                .copy_from_slice(lut_2i.as_ref());

            t1_j.get_mut_body()
                .as_mut()
                .copy_from_slice(lut_2i_plus_1.as_ref());

            t_fill[0] = 2;

            for (j, ggsw) in ggsw_list.into_ggsw_iter().rev().enumerate() {
                if t_fill[j] == 2 {
                    let (diff_data, stack) = stack.rb_mut().collect_aligned(
                        CACHELINE_ALIGN,
                        izip!(t1_j.as_ref(), t0_j.as_ref()).map(|(&a, &b)| a.wrapping_sub(b)),
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
                        add_external_product_assign(output, ggsw, diff, fft, stack);
                        t_fill[j + 1] += 1;
                        t_fill[j] = 0;

                        drop(diff_data);

                        (j_counter, t0_j, t1_j) = (j_counter_plus_1, t_0_j_plus_1, t_1_j_plus_1);
                    } else {
                        assert_eq!(j, nb_layer - 1);
                        let mut output = output_glwe.as_mut_view();
                        output.as_mut().copy_from_slice(t0_j.as_ref());
                        add_external_product_assign(output, ggsw, diff, fft, stack);
                    }
                } else {
                    break;
                }
            }
        }
    } else {
        output_glwe.get_mut_mask().as_mut().fill(Scalar::ZERO);
        output_glwe
            .get_mut_body()
            .as_mut()
            .copy_from_slice(lut_per_layer.as_ref());
    }
}
