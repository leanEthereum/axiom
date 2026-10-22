//! The ChaCha20 stream cipher of RFC 8439, section 2.4.

#[cfg(target_arch = "x86_64")]
use std::arch::is_x86_feature_detected;
use std::fmt;

#[cfg(target_arch = "x86_64")]
use super::avx2;
use crate::ct::wipe;

/// Bytes in one keystream block.
pub(crate) const BLOCK_LEN: usize = 64;

/// The words "expand 32-byte k" in little-endian, per RFC 8439, section 2.3.
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Index of the block counter in the state.
const COUNTER: usize = 12;

/// The ChaCha20 keystream, applied by XOR.
///
/// # Overview
///
/// The state is a 4 x 4 grid of 32-bit words, per RFC 8439, section 2.3.
///
/// ```text
/// cccccccc  cccccccc  cccccccc  cccccccc     c = constant
/// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk     k = key
/// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
/// bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn     b = block counter, n = nonce
/// ```
///
/// Each 64-byte block is the state after 20 rounds, added word-wise to the input state.
///
/// # Performance
///
/// On x86_64 with AVX2, eight blocks run side by side, one per 32-bit lane.
/// Tests pin that path to the portable one.
#[derive(Clone)]
pub struct ChaCha20 {
    /// The input state of the next block.
    state: [u32; 16],
    /// Keystream left over from a block a previous call cut short.
    leftover: [u8; BLOCK_LEN],
    /// Bytes of the leftover block already used, or 64 when none remain.
    used: usize,
    /// Blocks the 32-bit counter can still produce before it wraps.
    remaining_blocks: u64,
}

impl ChaCha20 {
    /// A keystream starting at the given block.
    #[must_use]
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        // The four constant words come first.
        let mut state = [0_u32; 16];
        state[..4].copy_from_slice(&SIGMA);

        // Key words 4 to 11, then counter word 12, then nonce words 13 to 15.
        let (key_words, _) = key.as_chunks::<4>();
        for (word, bytes) in state[4..12].iter_mut().zip(key_words) {
            *word = u32::from_le_bytes(*bytes);
        }
        state[COUNTER] = counter;
        let (nonce_words, _) = nonce.as_chunks::<4>();
        for (word, bytes) in state[13..].iter_mut().zip(nonce_words) {
            *word = u32::from_le_bytes(*bytes);
        }

        Self {
            state,
            leftover: [0; BLOCK_LEN],
            used: BLOCK_LEN,
            remaining_blocks: (1 << 32) - u64::from(counter),
        }
    }

    /// XORs the next keystream bytes into the data.
    ///
    /// Successive calls continue the stream where the last one stopped.
    ///
    /// # Panics
    ///
    /// Panics when the 32-bit block counter would wrap, past 256 GiB under one nonce.
    pub fn apply_keystream(&mut self, mut data: &mut [u8]) {
        // Phase 1: spend keystream left over from the previous call.
        let take = (BLOCK_LEN - self.used).min(data.len());
        let (head, rest) = data.split_at_mut(take);
        for (byte, key) in head.iter_mut().zip(&self.leftover[self.used..]) {
            *byte ^= key;
        }
        self.used += take;
        data = rest;

        // Phase 2: whole blocks, straight into the data.
        let whole = data.len() - data.len() % BLOCK_LEN;
        let (blocks, tail) = data.split_at_mut(whole);
        self.reserve_blocks(blocks.len() / BLOCK_LEN);
        self.xor_whole_blocks(blocks);

        // Phase 3: one more block for the tail, keeping the unused part.
        if !tail.is_empty() {
            self.reserve_blocks(1);
            self.leftover = self.next_block();
            for (byte, key) in tail.iter_mut().zip(&self.leftover) {
                *byte ^= key;
            }
            self.used = tail.len();
        }
    }

    /// One keystream block, advancing the counter.
    pub(crate) fn next_block(&mut self) -> [u8; BLOCK_LEN] {
        // Run the block function on the current state, then step the counter.
        let words = Self::block(&self.state);
        self.state[COUNTER] = self.state[COUNTER].wrapping_add(1);
        let mut out = [0_u8; BLOCK_LEN];
        let (chunks, _) = out.as_chunks_mut::<4>();
        for (chunk, word) in chunks.iter_mut().zip(words) {
            *chunk = word.to_le_bytes();
        }
        out
    }

    /// Claims blocks from the counter, refusing to wrap it.
    fn reserve_blocks(&mut self, blocks: usize) {
        // Invariant: a wrapped counter would repeat keystream, so refuse it.
        let blocks = blocks as u64;
        assert!(
            blocks <= self.remaining_blocks,
            "ChaCha20 block counter overflow"
        );
        self.remaining_blocks -= blocks;
    }

    /// XORs whole blocks with the fastest path the CPU supports.
    fn xor_whole_blocks(&mut self, data: &mut [u8]) {
        // Hardware path first.
        // It leaves fewer than eight blocks for the portable loop.
        #[cfg(target_arch = "x86_64")]
        let data = if is_x86_feature_detected!("avx2") {
            // Eight blocks at a time in the vector lanes.
            // The rest falls through.
            let batch = avx2::BLOCKS * BLOCK_LEN;
            let split = data.len() - data.len() % batch;
            let (wide, rest) = data.split_at_mut(split);
            for chunk in wide.as_chunks_mut::<{ avx2::BLOCKS * BLOCK_LEN }>().0 {
                // SAFETY: the CPU reports AVX2, the only feature the function enables.
                unsafe {
                    avx2::EightBlocks::xor_keystream(&self.state, chunk);
                }
                self.state[COUNTER] = self.state[COUNTER].wrapping_add(avx2::BLOCKS as u32);
            }
            rest
        } else {
            data
        };
        self.xor_whole_blocks_portable(data);
    }

    /// XORs whole blocks one at a time, the reference for every vector path.
    pub(crate) fn xor_whole_blocks_portable(&mut self, data: &mut [u8]) {
        // One 64-byte keystream block per 64 bytes of data.
        for chunk in data.as_chunks_mut::<BLOCK_LEN>().0 {
            let block = self.next_block();
            for (byte, key) in chunk.iter_mut().zip(block) {
                *byte ^= key;
            }
        }
    }

    /// The block function: 20 rounds over a copy, then the input state added back.
    ///
    /// # Algorithm
    ///
    /// Ten double rounds alternate columns and diagonals of the grid.
    ///
    /// ```text
    /// column round          diagonal round
    ///  0  1  2  3            0  1  2  3
    ///  4  5  6  7            5  6  7  4
    ///  8  9 10 11           10 11  8  9
    /// 12 13 14 15           15 12 13 14
    /// ```
    ///
    /// Each vertical line of four is one quarter round.
    pub(crate) fn block(input: &[u32; 16]) -> [u32; 16] {
        // Rounds run on a copy, so the input stays available for the feed-forward.
        let mut x = *input;
        for _ in 0..10 {
            // Column round: quarter rounds down the four columns.
            Self::quarter_round(&mut x, 0, 4, 8, 12);
            Self::quarter_round(&mut x, 1, 5, 9, 13);
            Self::quarter_round(&mut x, 2, 6, 10, 14);
            Self::quarter_round(&mut x, 3, 7, 11, 15);

            // Diagonal round: quarter rounds along the four diagonals.
            Self::quarter_round(&mut x, 0, 5, 10, 15);
            Self::quarter_round(&mut x, 1, 6, 11, 12);
            Self::quarter_round(&mut x, 2, 7, 8, 13);
            Self::quarter_round(&mut x, 3, 4, 9, 14);
        }

        // The feed-forward makes the block function non-invertible.
        for (word, initial) in x.iter_mut().zip(input) {
            *word = word.wrapping_add(*initial);
        }
        x
    }

    /// The add-rotate-xor quarter round of RFC 8439, section 2.1.
    #[inline]
    #[expect(clippy::many_single_char_names, reason = "the names follow RFC 8439")]
    const fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        // Four add-xor-rotate steps with rotations 16, 12, 8, 7.
        x[a] = x[a].wrapping_add(x[b]);
        x[d] = (x[d] ^ x[a]).rotate_left(16);
        x[c] = x[c].wrapping_add(x[d]);
        x[b] = (x[b] ^ x[c]).rotate_left(12);
        x[a] = x[a].wrapping_add(x[b]);
        x[d] = (x[d] ^ x[a]).rotate_left(8);
        x[c] = x[c].wrapping_add(x[d]);
        x[b] = (x[b] ^ x[c]).rotate_left(7);
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        // The state holds the key and the leftover holds keystream.
        wipe(&mut self.state);
        wipe(&mut self.leftover);
    }
}

impl fmt::Debug for ChaCha20 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The state holds the key: never print it.
        f.debug_struct("ChaCha20").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::{array, panic};

    use proptest::prelude::*;

    use super::*;

    /// Decodes a hex string in a test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The key 00 01 02 ... 1f used throughout RFC 8439.
    fn rfc_key() -> [u8; 32] {
        array::from_fn(|i| i as u8)
    }

    #[test]
    fn rfc_8439_quarter_round() {
        // RFC 8439, section 2.1.1: one quarter round on four words.
        let mut x = [0_u32; 16];
        x[..4].copy_from_slice(&[0x1111_1111, 0x0102_0304, 0x9b8d_6f43, 0x0123_4567]);
        ChaCha20::quarter_round(&mut x, 0, 1, 2, 3);
        assert_eq!(x[..4], [0xea2a_92f4, 0xcb1c_f8ce, 0x4581_472e, 0x5881_c4bb]);
    }

    #[test]
    fn rfc_8439_block_function() {
        // RFC 8439, section 2.3.2: block 1 under nonce 00:00:00:09:00:00:00:4a:00:00:00:00.
        let nonce: [u8; 12] = hex("000000090000004a00000000").try_into().unwrap();
        let block = ChaCha20::new(&rfc_key(), &nonce, 1).next_block();
        assert_eq!(
            block.to_vec(),
            hex(concat!(
                "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e",
                "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
            ))
        );
    }

    #[test]
    fn rfc_8439_encryption() {
        // RFC 8439, section 2.4.2: the "sunscreen" plaintext from counter 1, two blocks and a tail.
        let nonce: [u8; 12] = hex("000000000000004a00000000").try_into().unwrap();
        let mut data = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        ChaCha20::new(&rfc_key(), &nonce, 1).apply_keystream(&mut data);
        assert_eq!(
            data,
            hex(concat!(
                "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b",
                "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8",
                "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736",
                "5af90bbf74a35be6b40b8eedf2785e42874d",
            ))
        );
    }

    #[test]
    fn counter_overflow_is_refused() {
        // Counter 2^32 - 1 leaves exactly one block.
        let mut cipher = ChaCha20::new(&[0; 32], &[0; 12], u32::MAX);
        cipher.apply_keystream(&mut [0; 64]);

        // A second block would wrap the counter back to 0 and repeat keystream.
        let wrapped = panic::catch_unwind(move || cipher.apply_keystream(&mut [0; 1]));
        assert!(wrapped.is_err());
    }

    proptest! {
        #[test]
        fn pieces_encrypt_like_the_whole(
            data in prop::collection::vec(any::<u8>(), 0..1500),
            cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..5),
            counter in 0_u32..1000,
        ) {
            // Any split of the stream across calls gives the one-shot ciphertext.
            let mut whole = data.clone();
            ChaCha20::new(&rfc_key(), &[3; 12], counter).apply_keystream(&mut whole);

            let mut points: Vec<usize> = cuts.iter().map(|c| c.index(data.len() + 1)).collect();
            points.sort_unstable();
            let mut pieces = data;
            let mut cipher = ChaCha20::new(&rfc_key(), &[3; 12], counter);
            let mut start = 0;
            for point in points {
                cipher.apply_keystream(&mut pieces[start..point]);
                start = point;
            }
            cipher.apply_keystream(&mut pieces[start..]);
            prop_assert_eq!(pieces, whole);
        }

        #[test]
        fn dispatched_path_matches_the_portable_path(
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 12]>(),
            counter in prop_oneof![any::<u32>().prop_map(|c| c / 2), Just(u32::MAX - 40)],
            blocks in 0_usize..40,
        ) {
            // Whole blocks through the dispatcher, AVX2 when present, against block-by-block.
            // The second counter strategy runs a batch right up to the end of the counter range.
            let blocks = blocks.min((u32::MAX - counter) as usize + 1);
            let data: Vec<u8> = (0..blocks * BLOCK_LEN).map(|i| (i * 7) as u8).collect();
            let mut fast = data.clone();
            ChaCha20::new(&key, &nonce, counter).xor_whole_blocks(&mut fast);
            let mut reference = data;
            ChaCha20::new(&key, &nonce, counter).xor_whole_blocks_portable(&mut reference);
            prop_assert_eq!(fast, reference);
        }
    }
}
