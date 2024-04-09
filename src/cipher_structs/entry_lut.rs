use tfhe::integer::wopbs::{IntegerWopbsLUT, WopbsKey};
use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext, ServerKey};

/// A lookup table, taking (encrypted) `u8` as input, returning (encrypted) `u32`s.
///
/// Internally, this just stores four `u8 -> u8` lookup tables.
pub struct EntryLUT<'a> {
    lut: (
        IntegerWopbsLUT,
        IntegerWopbsLUT,
        IntegerWopbsLUT,
        IntegerWopbsLUT,
    ),
    server_key: &'a ServerKey,
    wopbs_key: &'a WopbsKey,
}

impl<'a> EntryLUT<'a> {
    pub fn new(entry: &'a Vec<u32>, server_key: &'a ServerKey, wopbs_key: &'a WopbsKey) -> Self {
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
        let f3 = |u: u64| -> u64 { (f(u) >> 24) % 256 }; //msb
        let lut = (
            wopbs_key.generate_lut_radix(&max_argument, f0),
            wopbs_key.generate_lut_radix(&max_argument, f1),
            wopbs_key.generate_lut_radix(&max_argument, f2),
            wopbs_key.generate_lut_radix(&max_argument, f3),
        );

        Self {
            lut,
            server_key,
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
}
