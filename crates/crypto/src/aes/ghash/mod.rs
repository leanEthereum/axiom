//! GHASH, the polynomial hash that authenticates GCM, per NIST SP 800-38D, section 6.4.

#[cfg(target_arch = "aarch64")]
mod aarch64_pmull;
mod backend;
mod gf128;
#[cfg(target_arch = "x86_64")]
mod x86_64_pclmul;

use std::slice;

use backend::Backend;
use gf128::Gf128;

use super::BLOCK_LEN;
use crate::ct::wipe;

/// A running GHASH under one hash key H.
///
/// # Overview
///
/// ```text
/// Y_0 = 0
/// Y_i = (Y_(i-1) ^ X_i) * H     in GF(2^128)
/// ```
pub(super) struct Ghash {
    /// H, H^2, H^3, H^4.
    powers: [Gf128; 4],
    /// The running value Y.
    acc: Gf128,
    /// The implementation chosen for this CPU, once, at construction.
    backend: Backend,
}

impl Ghash {
    /// A hash keyed by H = AES_K(0^128), on the fastest path the CPU supports.
    pub(super) fn new(h: &[u8; BLOCK_LEN]) -> Self {
        Self::with_backend(h, Backend::detect())
    }

    /// A hash keyed by H on a chosen path.
    fn with_backend(h: &[u8; BLOCK_LEN], backend: Backend) -> Self {
        // Four powers let the hardware paths fold four blocks per reduction.
        let h = Gf128::from_block(h);
        let h2 = h * h;
        let h3 = h2 * h;
        let h4 = h3 * h;
        Self {
            powers: [h, h2, h3, h4],
            acc: Gf128::ZERO,
            backend,
        }
    }

    /// Absorbs the data, then zeros up to the next block boundary.
    ///
    /// GCM pads the AAD and the ciphertext this way, per SP 800-38D, section 7.1.
    pub(super) fn update_padded(&mut self, data: &[u8]) {
        // Whole blocks go straight in.
        // A short tail is zero-padded to one more block.
        let (blocks, tail) = data.as_chunks::<BLOCK_LEN>();
        self.update_blocks(blocks);
        if !tail.is_empty() {
            let mut last = [0_u8; BLOCK_LEN];
            last[..tail.len()].copy_from_slice(tail);
            self.update_blocks(&[last]);
        }
    }

    /// Absorbs whole blocks.
    pub(super) fn update_blocks(&mut self, blocks: &[[u8; BLOCK_LEN]]) {
        self.acc = self.backend.absorb(&self.powers, self.acc, blocks);
    }

    /// The hash value Y, back in GCM's byte order.
    pub(super) const fn finalize(&self) -> [u8; BLOCK_LEN] {
        self.acc.to_block()
    }
}

impl Drop for Ghash {
    fn drop(&mut self) {
        // H is a secret derived from the key.
        wipe(&mut self.powers);
        wipe(slice::from_mut(&mut self.acc));
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Random bytes, in lengths around one block and the 4-block aggregation, then long ones.
    fn data() -> impl Strategy<Value = Vec<u8>> {
        let lengths = prop_oneof![
            prop::sample::select(vec![0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129]),
            0_usize..2000,
        ];
        lengths.prop_flat_map(|len| prop::collection::vec(any::<u8>(), len))
    }

    #[test]
    fn sp_800_38d_ghash_example() {
        // GCM test case 2 of McGrew and Viega: one ciphertext block, then the lengths.
        // The hash key is H = AES_0(0).
        let h = 0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2e_u128.to_be_bytes();
        let ciphertext = 0x0388_dace_60b6_a392_f328_c2b9_71b2_fe78_u128.to_be_bytes();
        let lengths = 0x0000_0000_0000_0000_0000_0000_0000_0080_u128.to_be_bytes();
        for backend in Backend::supported() {
            let mut ghash = Ghash::with_backend(&h, backend);
            ghash.update_blocks(&[ciphertext, lengths]);
            assert_eq!(
                ghash.finalize(),
                0xf38c_bb1a_d692_23dc_c345_7ae5_b6b0_f885_u128.to_be_bytes()
            );
        }
    }

    proptest! {
        #[test]
        fn every_path_matches_the_portable_path(
            h in any::<[u8; 16]>(),
            data in data(),
            split in any::<prop::sample::Index>(),
        ) {
            // Two uneven calls exercise the 4-block aggregation, its remainder, and padding.
            let at = split.index(data.len() + 1);
            let mut reference = Ghash::with_backend(&h, Backend::portable());
            reference.update_padded(&data[..at]);
            reference.update_padded(&data[at..]);
            for backend in Backend::supported() {
                let mut fast = Ghash::with_backend(&h, backend);
                fast.update_padded(&data[..at]);
                fast.update_padded(&data[at..]);
                prop_assert_eq!(fast.finalize(), reference.finalize());
            }
        }
    }
}
