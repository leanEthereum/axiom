//! AES-128 encryption with the x86_64 AES-NI instructions.
//!
//! # Overview
//!
//! AESENC performs exactly one FIPS 197 round, and AESENCLAST the last one.
//! The round keys come from the portable key schedule, so both paths share one expansion.
//!
//! The instructions take the same time for every key and block, with no table lookups.
//! No branch or address depends on a secret.

use std::arch::x86_64::{
    __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_loadu_si128, _mm_storeu_si128,
    _mm_xor_si128,
};

use super::portable::ROUNDS;

/// Blocks in flight at once.
///
/// AESENC has a latency of about 4 cycles and a throughput of 1 or 2 per cycle.
/// Eight independent blocks keep the pipeline full on every core since Westmere.
const LANES: usize = 8;

/// The eleven round keys loaded into vector registers.
#[derive(Clone, Copy, Debug)]
pub(super) struct NiSchedule([__m128i; ROUNDS + 1]);

impl NiSchedule {
    /// Encrypts every block in place under the round keys.
    ///
    /// Loading the keys and running the rounds share one target-feature boundary.
    /// The keys therefore stay in registers for the whole call.
    #[target_feature(enable = "aes,sse2")]
    pub(super) fn encrypt(keys: &[[u8; 16]; ROUNDS + 1], blocks: &mut [[u8; 16]]) {
        // Load the eleven round keys once for the whole call.
        Self(keys.map(|key| Self::load(&key))).encrypt_blocks(blocks);
    }

    /// Encrypts every block in place.
    ///
    /// AESENC performs exactly one FIPS 197 round: ShiftRows, SubBytes, MixColumns, AddRoundKey.
    /// AESENCLAST omits MixColumns, as the last round does.
    #[inline]
    #[target_feature(enable = "aes,sse2")]
    fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        let keys = &self.0;

        // Eight blocks at a time, round by round, so the eight AESENCs of a round overlap.
        let (groups, rest) = blocks.as_chunks_mut::<LANES>();
        for group in groups {
            let mut state = group.map(|block| _mm_xor_si128(Self::load(&block), keys[0]));
            for key in &keys[1..ROUNDS] {
                for lane in &mut state {
                    *lane = _mm_aesenc_si128(*lane, *key);
                }
            }
            for (block, lane) in group.iter_mut().zip(state) {
                Self::store(block, _mm_aesenclast_si128(lane, keys[ROUNDS]));
            }
        }

        // The remaining blocks one at a time.
        for block in rest {
            let mut state = _mm_xor_si128(Self::load(block), keys[0]);
            for key in &keys[1..ROUNDS] {
                state = _mm_aesenc_si128(state, *key);
            }
            Self::store(block, _mm_aesenclast_si128(state, keys[ROUNDS]));
        }
    }

    /// Loads 16 bytes into a register.
    #[inline]
    #[target_feature(enable = "sse2")]
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the unaligned load accepts any address"
    )]
    fn load(bytes: &[u8; 16]) -> __m128i {
        // SAFETY: the pointer covers 16 readable bytes, and unaligned loads accept any address.
        unsafe { _mm_loadu_si128(bytes.as_ptr().cast::<__m128i>()) }
    }

    /// Stores a register into 16 bytes.
    #[inline]
    #[target_feature(enable = "sse2")]
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the unaligned store accepts any address"
    )]
    fn store(bytes: &mut [u8; 16], value: __m128i) {
        // SAFETY: the pointer covers 16 writable bytes, and unaligned stores accept any address.
        unsafe { _mm_storeu_si128(bytes.as_mut_ptr().cast::<__m128i>(), value) }
    }
}
