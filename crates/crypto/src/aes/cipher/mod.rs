//! The AES-128 block cipher, encryption direction only, on every implementation the CPU offers.

#[cfg(target_arch = "aarch64")]
mod aarch64_aes;
mod backend;
mod portable;
#[cfg(target_arch = "x86_64")]
mod x86_64_aesni;

use std::{fmt, slice};

use backend::Backend;
use portable::RoundKeys;

use super::BLOCK_LEN;
use crate::ct::wipe;

/// Blocks encrypted per batch in counter mode, matching the hardware pipeline depth.
const BATCH: usize = 8;

/// The AES-128 block cipher, encryption direction only.
///
/// Counter mode and GCM never decrypt a block, so the inverse cipher is left out.
#[derive(Clone)]
pub struct Aes128 {
    /// The expanded key, cleared from memory when dropped.
    keys: RoundKeys,
    /// The implementation chosen for this CPU, once, at construction.
    backend: Backend,
}

impl Aes128 {
    /// Bytes in a key.
    pub const KEY_LEN: usize = 16;

    /// The cipher under one key, on the fastest path the CPU supports.
    #[must_use]
    pub fn new(key: &[u8; Self::KEY_LEN]) -> Self {
        Self::with_backend(key, Backend::detect())
    }

    /// The cipher under one key, on a chosen path.
    fn with_backend(key: &[u8; Self::KEY_LEN], backend: Backend) -> Self {
        Self {
            keys: backend.expand(key),
            backend,
        }
    }

    /// The cipher under one key, forced onto the portable path.
    #[cfg(test)]
    pub(crate) fn portable(key: &[u8; Self::KEY_LEN]) -> Self {
        Self::with_backend(key, Backend::portable())
    }

    /// Encrypts one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        // One block is a batch of one.
        self.encrypt_blocks(slice::from_mut(block));
    }

    /// Encrypts every block in place.
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_LEN]]) {
        self.backend.encrypt_blocks(&self.keys, blocks);
    }

    /// XORs the encrypted counter blocks into the data, eight blocks per batch.
    ///
    /// The counter function yields the next counter block on each call.
    /// A final partial block uses the head of its keystream block.
    pub(super) fn xor_keystream(
        &self,
        data: &mut [u8],
        mut next_counter: impl FnMut() -> [u8; BLOCK_LEN],
    ) {
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
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Random blocks, in counts around the 8-block pipeline, then long runs.
    fn blocks() -> impl Strategy<Value = Vec<[u8; 16]>> {
        let counts = prop_oneof![
            prop::sample::select(vec![0, 1, 7, 8, 9, 15, 16, 17]),
            0_usize..100,
        ];
        counts.prop_flat_map(|count| prop::collection::vec(any::<[u8; 16]>(), count))
    }

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
            // Every path the host runs, so the vectors pin each one, the reference included.
            for backend in Backend::supported() {
                let mut block = plaintext;
                Aes128::with_backend(&key, backend).encrypt_block(&mut block);
                assert_eq!(block, ciphertext);
            }
        }
    }

    proptest! {
        #[test]
        fn every_key_schedule_matches_the_portable_one(key in any::<[u8; 16]>()) {
            // A hardware schedule must produce the eleven round keys of FIPS 197 exactly.
            let reference = RoundKeys::expand(&key);
            for backend in Backend::supported() {
                let keys = backend.expand(&key);
                prop_assert_eq!(keys.as_blocks(), reference.as_blocks());
            }
        }

        #[test]
        fn every_path_matches_the_portable_path(key in any::<[u8; 16]>(), blocks in blocks()) {
            // Counts on both sides of each 8-block batch: every path equals the reference.
            let mut reference = blocks.clone();
            Aes128::portable(&key).encrypt_blocks(&mut reference);
            for backend in Backend::supported() {
                let mut fast = blocks.clone();
                Aes128::with_backend(&key, backend).encrypt_blocks(&mut fast);
                prop_assert_eq!(&fast, &reference);
            }
        }
    }
}
