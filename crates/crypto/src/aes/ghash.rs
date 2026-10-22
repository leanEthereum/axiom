//! GHASH, the polynomial hash that authenticates GCM, per NIST SP 800-38D, section 6.4.

#[cfg(target_arch = "x86_64")]
use std::arch::is_x86_feature_detected;
use std::slice;

#[cfg(target_arch = "x86_64")]
use super::clmul::ClmulGhash;
use super::{BLOCK_LEN, gf128::Gf128};
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
    /// Whether the CPU offers PCLMULQDQ and SSSE3.
    hardware: bool,
}

impl Ghash {
    /// A hash keyed by H = AES_K(0^128), on the fastest path the CPU supports.
    pub(super) fn new(h: &[u8; BLOCK_LEN]) -> Self {
        Self::with_path(h, Self::hardware_available())
    }

    /// A hash keyed by H on a chosen path.
    pub(super) fn with_path(h: &[u8; BLOCK_LEN], hardware: bool) -> Self {
        // Four powers let the hardware path fold four blocks per reduction.
        let h = Gf128::from_block(h);
        let h2 = h * h;
        let h3 = h2 * h;
        let h4 = h3 * h;
        Self {
            powers: [h, h2, h3, h4],
            acc: Gf128::ZERO,
            hardware,
        }
    }

    /// Whether this CPU runs the hardware path.
    #[cfg(target_arch = "x86_64")]
    fn hardware_available() -> bool {
        is_x86_feature_detected!("pclmulqdq") && is_x86_feature_detected!("ssse3")
    }

    /// Whether this CPU runs the hardware path.
    #[cfg(not(target_arch = "x86_64"))]
    const fn hardware_available() -> bool {
        false
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
        #[cfg(target_arch = "x86_64")]
        if self.hardware {
            // Both paths hold values in the natural bit order, so they share state.
            let powers = self.powers.map(Gf128::to_bits);
            // SAFETY: the flag is set only when the CPU reports PCLMULQDQ and SSSE3.
            // Those are the features the function enables.
            let acc = unsafe { ClmulGhash::update(&powers, self.acc.to_bits(), blocks) };
            self.acc = Gf128::from_bits(acc);
            return;
        }
        self.update_portable(blocks);
    }

    /// Absorbs whole blocks one at a time, the reference for the hardware path.
    fn update_portable(&mut self, blocks: &[[u8; BLOCK_LEN]]) {
        // Horner's rule, one block at a time.
        for block in blocks {
            self.acc = (self.acc ^ Gf128::from_block(block)) * self.powers[0];
        }
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

    #[test]
    fn sp_800_38d_ghash_example() {
        // GCM test case 2 of McGrew and Viega: one ciphertext block, then the lengths.
        // The hash key is H = AES_0(0).
        let h = 0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2e_u128.to_be_bytes();
        let ciphertext = 0x0388_dace_60b6_a392_f328_c2b9_71b2_fe78_u128.to_be_bytes();
        let lengths = 0x0000_0000_0000_0000_0000_0000_0000_0080_u128.to_be_bytes();
        for hardware in [false, Ghash::hardware_available()] {
            let mut ghash = Ghash::with_path(&h, hardware);
            ghash.update_blocks(&[ciphertext, lengths]);
            assert_eq!(
                ghash.finalize(),
                0xf38c_bb1a_d692_23dc_c345_7ae5_b6b0_f885_u128.to_be_bytes()
            );
        }
    }

    proptest! {
        #[test]
        fn hardware_path_matches_the_portable_path(
            h in any::<[u8; 16]>(),
            data in prop::collection::vec(any::<u8>(), 0..300),
            split in any::<prop::sample::Index>(),
        ) {
            // Two uneven calls exercise the 4-block aggregation and its remainder.
            let at = split.index(data.len() + 1);
            let mut fast = Ghash::new(&h);
            fast.update_padded(&data[..at]);
            fast.update_padded(&data[at..]);
            let mut reference = Ghash::with_path(&h, false);
            reference.update_padded(&data[..at]);
            reference.update_padded(&data[at..]);
            prop_assert_eq!(fast.finalize(), reference.finalize());
        }
    }
}
