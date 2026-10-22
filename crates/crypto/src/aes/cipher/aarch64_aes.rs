//! AES-128 with the ARMv8 cryptography extension.
//!
//! # Overview
//!
//! The extension splits a round differently from FIPS 197.
//!
//! ```text
//! AESE(s, k) = ShiftRows(SubBytes(s ^ k))
//! AESMC(s)   = MixColumns(s)
//! ```
//!
//! So the key addition opens each instruction pair instead of closing a round.
//!
//! ```text
//! s = AESMC(AESE(s, k_r))   for r = 0 .. 8
//! s = AESE(s, k_9) ^ k_10
//! ```
//!
//! This equals the ten FIPS 197 rounds after the initial whitening with k_0.
//!
//! The instructions take the same time for every key and block, with no table lookups.
//! No branch or address depends on a secret.

use std::arch::aarch64::{
    uint8x16_t, vaeseq_u8, vaesmcq_u8, vdupq_n_u8, vdupq_n_u32, veorq_u8, vgetq_lane_u32, vld1q_u8,
    vreinterpretq_u8_u32, vreinterpretq_u32_u8, vst1q_u8,
};

use super::portable::{RCON, ROUNDS};

/// Blocks in flight at once.
///
/// An AESE and AESMC pair fuses into one operation on most cores.
/// Its latency spans several cycles, so eight independent blocks keep the units busy.
const LANES: usize = 8;

/// The eleven round keys loaded into vector registers.
#[derive(Clone, Copy, Debug)]
pub(super) struct ArmSchedule([uint8x16_t; ROUNDS + 1]);

impl ArmSchedule {
    /// Expands a 128-bit key into eleven round keys, per FIPS 197, section 5.2.
    ///
    /// # Algorithm
    ///
    /// SubWord comes from AESE with a zero round key.
    /// The word is broadcast to all four columns first.
    /// Every row then holds one repeated byte, so ShiftRows leaves the state unchanged.
    /// Column 0 of the result is SubWord of the word.
    ///
    /// RotWord commutes with SubWord, since both act byte by byte.
    #[target_feature(enable = "aes")]
    pub(super) fn expand(key: &[u8; 16]) -> [[u8; 16]; ROUNDS + 1] {
        let mut keys = [[0_u8; 16]; ROUNDS + 1];
        keys[0] = *key;
        for round in 1..=ROUNDS {
            let previous = keys[round - 1];

            // The last word of the previous round key, bytes in little-endian order.
            let last = u32::from_le_bytes([previous[12], previous[13], previous[14], previous[15]]);

            // SubWord on all four columns at once, keeping column 0.
            let broadcast = vreinterpretq_u8_u32(vdupq_n_u32(last));
            let substituted = vaeseq_u8(broadcast, vdupq_n_u8(0));
            let sub_word = vgetq_lane_u32::<0>(vreinterpretq_u32_u8(substituted));

            // RotWord moves byte 0 to byte 3: a right rotation of the little-endian word.
            let word = sub_word.rotate_right(8) ^ u32::from(RCON[round - 1]);

            // Each word chains off the word before it.
            let mut next = [0_u8; 16];
            let mut chained = word;
            for (column, out) in next.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                let start = 4 * column;
                let prior = [
                    previous[start],
                    previous[start + 1],
                    previous[start + 2],
                    previous[start + 3],
                ];
                chained ^= u32::from_le_bytes(prior);
                *out = chained.to_le_bytes();
            }
            keys[round] = next;
        }
        keys
    }

    /// Encrypts every block in place under the round keys.
    ///
    /// Loading the keys and running the rounds share one target-feature boundary.
    /// The keys therefore stay in registers for the whole call.
    #[target_feature(enable = "aes")]
    pub(super) fn encrypt(keys: &[[u8; 16]; ROUNDS + 1], blocks: &mut [[u8; 16]]) {
        // Load the eleven round keys once for the whole call.
        Self(keys.map(|key| Self::load(&key))).encrypt_blocks(blocks);
    }

    /// Encrypts every block in place.
    #[inline]
    #[target_feature(enable = "aes")]
    fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        let keys = &self.0;

        // Eight blocks at a time, round by round, so the eight pairs of a round overlap.
        let (groups, rest) = blocks.as_chunks_mut::<LANES>();
        for group in groups {
            let mut state = group.map(|block| Self::load(&block));
            for key in &keys[..ROUNDS - 1] {
                for lane in &mut state {
                    *lane = vaesmcq_u8(vaeseq_u8(*lane, *key));
                }
            }
            for (block, lane) in group.iter_mut().zip(state) {
                Self::store(block, Self::last_round(lane, keys));
            }
        }

        // The remaining blocks one at a time.
        for block in rest {
            let mut state = Self::load(block);
            for key in &keys[..ROUNDS - 1] {
                state = vaesmcq_u8(vaeseq_u8(state, *key));
            }
            Self::store(block, Self::last_round(state, keys));
        }
    }

    /// The final round: no MixColumns, then the last round key.
    #[inline]
    #[target_feature(enable = "aes")]
    fn last_round(state: uint8x16_t, keys: &[uint8x16_t; ROUNDS + 1]) -> uint8x16_t {
        veorq_u8(vaeseq_u8(state, keys[ROUNDS - 1]), keys[ROUNDS])
    }

    /// Loads 16 bytes into a register, byte i into lane i.
    #[inline]
    #[target_feature(enable = "neon")]
    fn load(bytes: &[u8; 16]) -> uint8x16_t {
        // SAFETY: the pointer covers 16 readable bytes, and the load has no alignment requirement.
        unsafe { vld1q_u8(bytes.as_ptr()) }
    }

    /// Stores a register into 16 bytes, lane i into byte i.
    #[inline]
    #[target_feature(enable = "neon")]
    fn store(bytes: &mut [u8; 16], value: uint8x16_t) {
        // SAFETY: the pointer covers 16 writable bytes, and the store has no alignment requirement.
        unsafe { vst1q_u8(bytes.as_mut_ptr(), value) }
    }
}
