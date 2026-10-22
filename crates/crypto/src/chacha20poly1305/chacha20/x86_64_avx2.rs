//! Eight ChaCha20 blocks at once in AVX2 registers.
//!
//! # Overview
//!
//! Each 32-bit lane runs the scalar block function of RFC 8439 on its own block.
//! Lane-wise addition, XOR and rotation are the scalar operations, so every lane equals the reference.
//!
//! Additions, XORs, shifts and shuffles take the same time for every value.
//! No branch or address depends on the key or the keystream.

use std::arch::x86_64::{
    __m256i, _mm256_add_epi32, _mm256_loadu_si256, _mm256_or_si256, _mm256_permute2x128_si256,
    _mm256_set1_epi32, _mm256_setr_epi8, _mm256_setr_epi32, _mm256_shuffle_epi8, _mm256_slli_epi32,
    _mm256_srli_epi32, _mm256_storeu_si256, _mm256_unpackhi_epi32, _mm256_unpackhi_epi64,
    _mm256_unpacklo_epi32, _mm256_unpacklo_epi64, _mm256_xor_si256,
};

use super::BLOCK_LEN;

/// Blocks per call: one per 32-bit lane of a 256-bit register.
pub(super) const BLOCKS: usize = 8;

/// Eight ChaCha20 states side by side: row i holds word i of every block, one block per lane.
#[derive(Clone, Copy, Debug)]
pub(super) struct EightBlocks([__m256i; 16]);

impl EightBlocks {
    /// XORs eight consecutive keystream blocks into 512 bytes of data.
    ///
    /// The counter of the given state is the first block's.
    /// The caller advances it by eight afterwards, and guarantees the eight counters do not wrap.
    ///
    /// # Algorithm
    ///
    /// Register i holds word i of all eight blocks, so the rounds are the scalar code verbatim.
    ///
    /// ```text
    ///            lane 0   lane 1   ...  lane 7
    /// v[0]    :  b0.w0    b1.w0    ...  b7.w0
    /// v[12]   :  ctr      ctr+1    ...  ctr+7
    /// v[15]   :  b0.w15   b1.w15   ...  b7.w15
    /// ```
    ///
    /// A final 8 x 8 transpose turns each column back into one block's bytes.
    #[target_feature(enable = "avx2")]
    pub(super) fn xor_keystream(state: &[u32; 16], data: &mut [u8; BLOCKS * BLOCK_LEN]) {
        // Phase 1: eight copies of the state, each lane with its own counter.
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

    /// Eight copies of the state, lane j counting j blocks past the state's counter.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn broadcast(state: &[u32; 16]) -> Self {
        // Broadcast every state word, then give each lane its own counter.
        let mut rows = [_mm256_set1_epi32(0); 16];
        for (row, &word) in rows.iter_mut().zip(state) {
            *row = _mm256_set1_epi32(word.cast_signed());
        }
        rows[12] = _mm256_add_epi32(rows[12], _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));
        Self(rows)
    }

    /// One double round: four column rounds, then four diagonal rounds.
    #[inline]
    #[target_feature(enable = "avx2")]
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

    /// The quarter round of RFC 8439, section 2.1, on eight lanes.
    #[inline]
    #[target_feature(enable = "avx2")]
    #[expect(clippy::many_single_char_names, reason = "the names follow RFC 8439")]
    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize) {
        // The scalar quarter round, lane-wise: add, XOR, rotate, four times.
        let x = &mut self.0;
        x[a] = _mm256_add_epi32(x[a], x[b]);
        x[d] = Self::rotate::<16, 16>(_mm256_xor_si256(x[d], x[a]));
        x[c] = _mm256_add_epi32(x[c], x[d]);
        x[b] = Self::rotate::<12, 20>(_mm256_xor_si256(x[b], x[c]));
        x[a] = _mm256_add_epi32(x[a], x[b]);
        x[d] = Self::rotate::<8, 24>(_mm256_xor_si256(x[d], x[a]));
        x[c] = _mm256_add_epi32(x[c], x[d]);
        x[b] = Self::rotate::<7, 25>(_mm256_xor_si256(x[b], x[c]));
    }

    /// Adds other rows, word by word.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn add(&mut self, other: &Self) {
        // Lane-wise 32-bit addition, as the scalar feed-forward does per word.
        for (row, start) in self.0.iter_mut().zip(other.0) {
            *row = _mm256_add_epi32(*row, start);
        }
    }

    /// XORs the eight blocks, in block order, into 512 bytes of data.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn xor_into(&self, data: &mut [u8; BLOCKS * BLOCK_LEN]) {
        // Words 0..7 and words 8..15 each transpose into the halves of the eight blocks.
        //
        //     low[j]  = words 0..7 of block j   -> bytes 64j .. 64j + 32
        //     high[j] = words 8..15 of block j  -> bytes 64j + 32 .. 64j + 64
        let (rows, _) = self.0.as_chunks::<8>();
        let low = Self::transpose(&rows[0]);
        let high = Self::transpose(&rows[1]);
        let (halves, _) = data.as_chunks_mut::<32>();
        for (block, (low, high)) in low.into_iter().zip(high).enumerate() {
            Self::xor_half(&mut halves[2 * block], low);
            Self::xor_half(&mut halves[2 * block + 1], high);
        }
    }

    /// Rotates every 32-bit lane left.
    ///
    /// The second parameter must equal 32 minus the first.
    /// Whole-byte rotations take one byte shuffle instead of two shifts and an OR.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn rotate<const LEFT: i32, const RIGHT: i32>(v: __m256i) -> __m256i {
        // The parameters are constants, so only one arm survives compilation.
        if LEFT == 16 {
            // Byte k of a lane comes from byte (k + 2) mod 4: the two halves swap.
            let order = _mm256_setr_epi8(
                2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10,
                11, 8, 9, 14, 15, 12, 13,
            );
            _mm256_shuffle_epi8(v, order)
        } else if LEFT == 8 {
            // Byte k of a lane comes from byte (k + 3) mod 4: the top byte wraps to the bottom.
            let order = _mm256_setr_epi8(
                3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11,
                8, 9, 10, 15, 12, 13, 14,
            );
            _mm256_shuffle_epi8(v, order)
        } else {
            _mm256_or_si256(_mm256_slli_epi32::<LEFT>(v), _mm256_srli_epi32::<RIGHT>(v))
        }
    }

    /// Transposes eight registers of eight 32-bit lanes.
    ///
    /// # Algorithm
    ///
    /// Row r_i holds word i of blocks 0..7.
    /// Output j holds words 0..7 of block j.
    ///
    /// ```text
    /// unpack 32 : [r0.0 r1.0 r0.1 r1.1 | r0.4 r1.4 r0.5 r1.5]   pairs of rows
    /// unpack 64 : [r0.0 r1.0 r2.0 r3.0 | r0.4 r1.4 r2.4 r3.4]   quads of rows
    /// permute   : [r0.0 .. r3.0 | r4.0 .. r7.0]                 block 0 whole
    /// ```
    #[inline]
    #[target_feature(enable = "avx2")]
    fn transpose(rows: &[__m256i; 8]) -> [__m256i; 8] {
        // Stage 1: interleave pairs of rows at 32-bit granularity.
        let t0 = _mm256_unpacklo_epi32(rows[0], rows[1]);
        let t1 = _mm256_unpackhi_epi32(rows[0], rows[1]);
        let t2 = _mm256_unpacklo_epi32(rows[2], rows[3]);
        let t3 = _mm256_unpackhi_epi32(rows[2], rows[3]);
        let t4 = _mm256_unpacklo_epi32(rows[4], rows[5]);
        let t5 = _mm256_unpackhi_epi32(rows[4], rows[5]);
        let t6 = _mm256_unpacklo_epi32(rows[6], rows[7]);
        let t7 = _mm256_unpackhi_epi32(rows[6], rows[7]);

        // Stage 2: interleave pairs of pairs at 64-bit granularity.
        //
        //     u0 : columns 0 and 4 of rows 0..3
        //     u1 : columns 1 and 5, u2 : columns 2 and 6, u3 : columns 3 and 7
        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        let u4 = _mm256_unpacklo_epi64(t4, t6);
        let u5 = _mm256_unpackhi_epi64(t4, t6);
        let u6 = _mm256_unpacklo_epi64(t5, t7);
        let u7 = _mm256_unpackhi_epi64(t5, t7);

        // Stage 3: join the 128-bit halves.
        // Selector 0x20 takes both lows, 0x31 both highs.
        [
            _mm256_permute2x128_si256::<0x20>(u0, u4),
            _mm256_permute2x128_si256::<0x20>(u1, u5),
            _mm256_permute2x128_si256::<0x20>(u2, u6),
            _mm256_permute2x128_si256::<0x20>(u3, u7),
            _mm256_permute2x128_si256::<0x31>(u0, u4),
            _mm256_permute2x128_si256::<0x31>(u1, u5),
            _mm256_permute2x128_si256::<0x31>(u2, u6),
            _mm256_permute2x128_si256::<0x31>(u3, u7),
        ]
    }

    /// XORs 32 keystream bytes into 32 data bytes.
    #[inline]
    #[target_feature(enable = "avx2")]
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the unaligned load and store accept any address"
    )]
    fn xor_half(data: &mut [u8; 32], keystream: __m256i) {
        // Unaligned access: the data has no alignment guarantee.
        let pointer = data.as_mut_ptr().cast::<__m256i>();
        // SAFETY: the pointer covers 32 writable bytes, and unaligned accesses accept any address.
        unsafe {
            let mixed = _mm256_xor_si256(_mm256_loadu_si256(pointer), keystream);
            _mm256_storeu_si256(pointer, mixed);
        }
    }
}
