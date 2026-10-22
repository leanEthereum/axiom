//! Four ChaCha20 blocks at once in NEON registers.
//!
//! # Overview
//!
//! Each 32-bit lane runs the scalar block function of RFC 8439 on its own block.
//! Lane-wise addition, XOR and rotation are the scalar operations, so every lane equals the reference.
//!
//! Additions, XORs, shifts and table permutes take the same time for every value.
//! The permute indices are constants, so no branch or address depends on the key or the keystream.
//!
//! The final store writes 32-bit lanes as bytes in register order.
//! That order is little-endian only on a little-endian target, so the module declaration requires one.

use std::arch::aarch64::{
    uint32x4_t, vaddq_u32, vdupq_n_u32, veorq_u8, veorq_u32, vld1q_u8, vld1q_u32, vqtbl1q_u8,
    vreinterpretq_u8_u32, vreinterpretq_u16_u32, vreinterpretq_u32_u8, vreinterpretq_u32_u16,
    vreinterpretq_u32_u64, vreinterpretq_u64_u32, vrev32q_u16, vshlq_n_u32, vsriq_n_u32, vst1q_u8,
    vtrn1q_u32, vtrn1q_u64, vtrn2q_u32, vtrn2q_u64,
};

use super::BLOCK_LEN;

/// Blocks per call: one per 32-bit lane of a 128-bit register.
pub(super) const BLOCKS: usize = 4;

/// Lane offsets of the block counter: lane j encrypts block j of the batch.
const COUNTER_STEPS: [u32; BLOCKS] = [0, 1, 2, 3];

/// Byte permutation that rotates every 32-bit lane left by 8 bits.
///
/// Byte k of a lane comes from byte (k + 3) mod 4, so the top byte wraps to the bottom.
const ROTATE_8: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];

/// Four ChaCha20 states side by side: row i holds word i of every block, one block per lane.
#[derive(Clone, Copy, Debug)]
pub(super) struct FourBlocks([uint32x4_t; 16]);

impl FourBlocks {
    /// XORs four consecutive keystream blocks into 256 bytes of data.
    ///
    /// The counter of the given state is the first block's.
    /// The caller advances it by four afterwards, and guarantees the four counters do not wrap.
    ///
    /// # Algorithm
    ///
    /// Register i holds word i of all four blocks, so the rounds are the scalar code verbatim.
    ///
    /// ```text
    ///            lane 0   lane 1   lane 2   lane 3
    /// v[0]    :  b0.w0    b1.w0    b2.w0    b3.w0
    /// v[12]   :  ctr      ctr+1    ctr+2    ctr+3
    /// v[15]   :  b0.w15   b1.w15   b2.w15   b3.w15
    /// ```
    ///
    /// Four 4 x 4 transposes turn each column back into one block's bytes.
    #[target_feature(enable = "neon")]
    pub(super) fn xor_keystream(state: &[u32; 16], data: &mut [u8; BLOCKS * BLOCK_LEN]) {
        // Phase 1: four copies of the state, each lane with its own counter.
        let initial = Self::broadcast(state);

        // Phase 2: ten double rounds, as in the scalar block function.
        let mut rows = initial;
        for _ in 0..10 {
            rows.double_round();
        }

        // Phase 3: the feed-forward of the input state.
        rows.add(&initial);

        // Phase 4: back to block order, XORed into the data.
        rows.xor_into(data);
    }

    /// Four copies of the state, lane j counting j blocks past the state's counter.
    #[inline]
    #[target_feature(enable = "neon")]
    fn broadcast(state: &[u32; 16]) -> Self {
        // Broadcast every state word, then give each lane its own counter.
        let mut rows = [vdupq_n_u32(0); 16];
        for (row, &word) in rows.iter_mut().zip(state) {
            *row = vdupq_n_u32(word);
        }
        // SAFETY: the pointer covers four readable words, and the load has no alignment requirement.
        let steps = unsafe { vld1q_u32(COUNTER_STEPS.as_ptr()) };
        rows[12] = vaddq_u32(rows[12], steps);
        Self(rows)
    }

    /// One double round: four column rounds, then four diagonal rounds.
    #[inline]
    #[target_feature(enable = "neon")]
    fn double_round(&mut self) {
        // The index pattern of the scalar double round, RFC 8439, section 2.3.
        self.quarter_round(0, 4, 8, 12);
        self.quarter_round(1, 5, 9, 13);
        self.quarter_round(2, 6, 10, 14);
        self.quarter_round(3, 7, 11, 15);
        self.quarter_round(0, 5, 10, 15);
        self.quarter_round(1, 6, 11, 12);
        self.quarter_round(2, 7, 8, 13);
        self.quarter_round(3, 4, 9, 14);
    }

    /// The quarter round of RFC 8439, section 2.1, on four lanes.
    #[inline]
    #[target_feature(enable = "neon")]
    #[expect(clippy::many_single_char_names, reason = "the names follow RFC 8439")]
    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize) {
        // The scalar quarter round, lane-wise: add, XOR, rotate, four times.
        let x = &mut self.0;
        x[a] = vaddq_u32(x[a], x[b]);
        x[d] = Self::rotate_16(veorq_u32(x[d], x[a]));
        x[c] = vaddq_u32(x[c], x[d]);
        x[b] = Self::rotate::<12, 20>(veorq_u32(x[b], x[c]));
        x[a] = vaddq_u32(x[a], x[b]);
        x[d] = Self::rotate_8(veorq_u32(x[d], x[a]));
        x[c] = vaddq_u32(x[c], x[d]);
        x[b] = Self::rotate::<7, 25>(veorq_u32(x[b], x[c]));
    }

    /// Adds other rows, word by word.
    #[inline]
    #[target_feature(enable = "neon")]
    fn add(&mut self, other: &Self) {
        // Lane-wise 32-bit addition, as the scalar feed-forward does per word.
        for (row, start) in self.0.iter_mut().zip(other.0) {
            *row = vaddq_u32(*row, start);
        }
    }

    /// XORs the four blocks, in block order, into 256 bytes of data.
    #[inline]
    #[target_feature(enable = "neon")]
    fn xor_into(&self, data: &mut [u8; BLOCKS * BLOCK_LEN]) {
        // Rows 4g..4g+3 transpose into words 4g..4g+3 of each block.
        //
        //     block j, words 4g..4g+3  ->  bytes 64j + 16g .. 64j + 16g + 16
        let (groups, _) = self.0.as_chunks::<4>();
        let (pieces, _) = data.as_chunks_mut::<16>();
        for (group, rows) in groups.iter().enumerate() {
            for (block, words) in Self::transpose(rows).into_iter().enumerate() {
                Self::xor_piece(&mut pieces[4 * block + group], words);
            }
        }
    }

    /// Rotates every 32-bit lane left by 16 bits, by swapping its two halves.
    #[inline]
    #[target_feature(enable = "neon")]
    fn rotate_16(v: uint32x4_t) -> uint32x4_t {
        vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)))
    }

    /// Rotates every 32-bit lane left by 8 bits, with one table permute.
    #[inline]
    #[target_feature(enable = "neon")]
    fn rotate_8(v: uint32x4_t) -> uint32x4_t {
        // SAFETY: the pointer covers 16 readable bytes, and the load has no alignment requirement.
        let order = unsafe { vld1q_u8(ROTATE_8.as_ptr()) };
        vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(v), order))
    }

    /// Rotates every 32-bit lane left.
    ///
    /// The second parameter must equal 32 minus the first.
    ///
    /// ```text
    /// rotl(v, L) = (v << L) | (v >> (32 - L))
    /// ```
    ///
    /// The shift-right-and-insert writes the low bits into the shifted copy in one instruction.
    #[inline]
    #[target_feature(enable = "neon")]
    fn rotate<const LEFT: i32, const RIGHT: i32>(v: uint32x4_t) -> uint32x4_t {
        vsriq_n_u32::<RIGHT>(vshlq_n_u32::<LEFT>(v), v)
    }

    /// Transposes four registers of four 32-bit lanes.
    ///
    /// # Algorithm
    ///
    /// Row r_i holds word i of blocks 0..3.
    /// Output j holds the four words of block j.
    ///
    /// ```text
    /// trn 32 : [r0.0 r1.0 r0.2 r1.2]   [r0.1 r1.1 r0.3 r1.3]   pairs of rows
    /// trn 64 : [r0.0 r1.0 r2.0 r3.0]                           block 0 whole
    /// ```
    #[inline]
    #[target_feature(enable = "neon")]
    fn transpose(rows: &[uint32x4_t; 4]) -> [uint32x4_t; 4] {
        // Stage 1: interleave pairs of rows at 32-bit granularity.
        let t0 = vreinterpretq_u64_u32(vtrn1q_u32(rows[0], rows[1]));
        let t1 = vreinterpretq_u64_u32(vtrn2q_u32(rows[0], rows[1]));
        let t2 = vreinterpretq_u64_u32(vtrn1q_u32(rows[2], rows[3]));
        let t3 = vreinterpretq_u64_u32(vtrn2q_u32(rows[2], rows[3]));

        // Stage 2: interleave the pairs at 64-bit granularity.
        [
            vreinterpretq_u32_u64(vtrn1q_u64(t0, t2)),
            vreinterpretq_u32_u64(vtrn1q_u64(t1, t3)),
            vreinterpretq_u32_u64(vtrn2q_u64(t0, t2)),
            vreinterpretq_u32_u64(vtrn2q_u64(t1, t3)),
        ]
    }

    /// XORs 16 keystream bytes into 16 data bytes.
    #[inline]
    #[target_feature(enable = "neon")]
    fn xor_piece(data: &mut [u8; 16], keystream: uint32x4_t) {
        let pointer = data.as_mut_ptr();
        // SAFETY: the pointer covers 16 readable and writable bytes.
        // NEON loads and stores have no alignment requirement.
        unsafe {
            let mixed = veorq_u8(vld1q_u8(pointer), vreinterpretq_u8_u32(keystream));
            vst1q_u8(pointer, mixed);
        }
    }
}
