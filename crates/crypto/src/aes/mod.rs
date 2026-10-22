//! AES-128 with its CTR and GCM modes, the ciphers of discv5 packets.
//!
//! # Overview
//!
//! discv5 uses two modes of one block cipher.
//!
//! - AES-128-CTR masks each packet header under the destination node's identifier.
//! - AES-128-GCM seals each message under a session key.
//!
//! # Performance
//!
//! On x86_64, AES-NI encrypts and PCLMULQDQ multiplies in GHASH, both detected at run time.
//! Elsewhere a bitsliced, table-free AES and a constant-time carry-less multiply take over.
//! Property tests pin each hardware path to its portable reference.

#[cfg(target_arch = "x86_64")]
mod clmul;
mod ctr;
mod gcm;
mod gf128;
mod ghash;
#[cfg(target_arch = "x86_64")]
mod ni;
mod sbox;
mod soft;
mod state;

#[cfg(target_arch = "x86_64")]
use std::arch::is_x86_feature_detected;
use std::{fmt, slice};

pub use ctr::Aes128Ctr;
pub use gcm::Aes128Gcm;
#[cfg(target_arch = "x86_64")]
use ni::NiSchedule;
use soft::RoundKeys;

use crate::ct::wipe;

/// Bytes in one AES block.
const BLOCK_LEN: usize = 16;

/// Blocks encrypted per batch in counter mode, matching the AES-NI pipeline depth.
const BATCH: usize = 8;

/// The AES-128 block cipher, encryption direction only.
///
/// Counter mode and GCM never decrypt a block, so the inverse cipher is left out.
///
/// # Examples
///
/// ```
/// use axiom_crypto::aes::Aes128;
///
/// // FIPS 197, appendix C.1.
/// let key: [u8; 16] = std::array::from_fn(|i| i as u8);
/// let mut block: [u8; 16] = std::array::from_fn(|i| (i as u8) * 0x11);
/// Aes128::new(&key).encrypt_block(&mut block);
/// assert_eq!(block[..4], [0x69, 0xc4, 0xe0, 0xd8]);
/// ```
#[derive(Clone)]
pub struct Aes128 {
    /// The expanded key, cleared from memory when dropped.
    keys: RoundKeys,
    /// Whether the CPU offers AES-NI, checked once at construction.
    hardware: bool,
}

impl Aes128 {
    /// Bytes in a key.
    pub const KEY_LEN: usize = 16;

    /// The cipher under one key, on the fastest path the CPU supports.
    #[must_use]
    pub fn new(key: &[u8; Self::KEY_LEN]) -> Self {
        Self {
            keys: RoundKeys::expand(key),
            hardware: Self::hardware_available(),
        }
    }

    /// The cipher under one key, forced onto the portable path.
    #[cfg(test)]
    pub(crate) fn portable(key: &[u8; Self::KEY_LEN]) -> Self {
        Self {
            keys: RoundKeys::expand(key),
            hardware: false,
        }
    }

    /// Whether this CPU runs the hardware path.
    #[cfg(target_arch = "x86_64")]
    fn hardware_available() -> bool {
        is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2")
    }

    /// Whether this CPU runs the hardware path.
    #[cfg(not(target_arch = "x86_64"))]
    const fn hardware_available() -> bool {
        false
    }

    /// Encrypts one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        // One block is a batch of one.
        self.encrypt_blocks(slice::from_mut(block));
    }

    /// Encrypts every block in place.
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]]) {
        // Hardware path: AES-NI, eight blocks in flight.
        #[cfg(target_arch = "x86_64")]
        if self.hardware {
            // SAFETY: the flag is set only when the CPU reports AES-NI and SSE2.
            // Those are the features the function enables.
            unsafe {
                NiSchedule::encrypt(self.keys.as_blocks(), blocks);
            }
            return;
        }
        for block in blocks {
            self.keys.encrypt_block(block);
        }
    }

    /// XORs the encrypted counter blocks into the data, eight blocks per batch.
    ///
    /// The counter function yields the next counter block on each call.
    /// A final partial block uses the head of its keystream block.
    fn xor_keystream(&self, data: &mut [u8], mut next_counter: impl FnMut() -> [u8; BLOCK_LEN]) {
        for chunk in data.chunks_mut(BATCH * BLOCK_LEN) {
            // Fill only as many counter blocks as the chunk needs.
            let used = chunk.len().div_ceil(BLOCK_LEN);
            let mut keystream = [[0_u8; BLOCK_LEN]; BATCH];
            for block in &mut keystream[..used] {
                *block = next_counter();
            }
            self.encrypt_blocks(&mut keystream[..used]);
            for (byte, key) in chunk.iter_mut().zip(keystream.as_flattened()) {
                *byte ^= key;
            }
            wipe(keystream.as_flattened_mut());
        }
    }
}

impl fmt::Debug for Aes128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The round keys are secret: never print them.
        f.debug_struct("Aes128")
            .field("hardware", &self.hardware)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn fips_197_vectors() {
        // Appendix B: the worked example.
        // Appendix C.1: the AES-128 known answer.
        let cases = [
            (
                [
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ],
                [
                    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0,
                    0x37, 0x07, 0x34,
                ],
                [
                    0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19,
                    0x6a, 0x0b, 0x32,
                ],
            ),
            (
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ],
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
                [
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70,
                    0xb4, 0xc5, 0x5a,
                ],
            ),
        ];
        for (key, plaintext, ciphertext) in cases {
            // Both paths, so the vectors pin the reference even on a CPU with AES-NI.
            for cipher in [Aes128::new(&key), Aes128::portable(&key)] {
                let mut block = plaintext;
                cipher.encrypt_block(&mut block);
                assert_eq!(block, ciphertext);
            }
        }
    }

    proptest! {
        #[test]
        fn hardware_path_matches_the_portable_path(
            key in any::<[u8; 16]>(),
            blocks in prop::collection::vec(any::<[u8; 16]>(), 0..20),
        ) {
            // Every batch size from 0 to 19 crosses the 8-block pipeline boundary.
            let mut fast = blocks.clone();
            Aes128::new(&key).encrypt_blocks(&mut fast);
            let mut reference = blocks;
            Aes128::portable(&key).encrypt_blocks(&mut reference);
            prop_assert_eq!(fast, reference);
        }
    }
}
