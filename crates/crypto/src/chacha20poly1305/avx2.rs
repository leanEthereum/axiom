//! Eight ChaCha20 blocks at once in AVX2 registers.

use std::arch::x86_64::{
    __m256i, _mm256_add_epi32, _mm256_loadu_si256, _mm256_or_si256, _mm256_permute2x128_si256,
    _mm256_set1_epi32, _mm256_setr_epi8, _mm256_setr_epi32, _mm256_shuffle_epi8, _mm256_slli_epi32,
    _mm256_srli_epi32, _mm256_storeu_si256, _mm256_unpackhi_epi32, _mm256_unpackhi_epi64,
    _mm256_unpacklo_epi32, _mm256_unpacklo_epi64, _mm256_xor_si256,
};

use super::chacha20::BLOCK_LEN;

/// Blocks per call: one per 32-bit lane of a 256-bit register.
pub(crate) const BLOCKS: usize = 8;

/// XORs eight consecutive keystream blocks into 512 bytes of data.
///
/// The counter of the given state is the first block's.
/// The caller advances it by eight afterwards.
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
pub(crate) fn xor_blocks(state: &[u32; 16], data: &mut [u8; BLOCKS * BLOCK_LEN]) {
    // Phase 1: broadcast every state word, then give each lane its own counter.
    let mut initial = [_mm256_set1_epi32(0); 16];
    for (vector, &word) in initial.iter_mut().zip(state) {
        *vector = _mm256_set1_epi32(word.cast_signed());
    }
    initial[12] = _mm256_add_epi32(initial[12], _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));

    // Phase 2: ten double rounds, columns then diagonals, as in the scalar block function.
    let mut x = initial;
    for _ in 0..10 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }

    // Phase 3: the feed-forward of the input state.
    for (vector, start) in x.iter_mut().zip(initial) {
        *vector = _mm256_add_epi32(*vector, start);
    }

    // Phase 4: words 0..7 and words 8..15 each transpose into the halves of the eight blocks.
    //
    //     low[j]  = words 0..7 of block j   -> bytes 64j .. 64j + 32
    //     high[j] = words 8..15 of block j  -> bytes 64j + 32 .. 64j + 64
    let low = transpose(&x[..8]);
    let high = transpose(&x[8..]);
    let (halves, _) = data.as_chunks_mut::<32>();
    for (block, (low, high)) in low.into_iter().zip(high).enumerate() {
        xor_into(&mut halves[2 * block], low);
        xor_into(&mut halves[2 * block + 1], high);
    }
}

/// The quarter round of RFC 8439, section 2.1, on eight lanes.
#[inline]
#[target_feature(enable = "avx2")]
#[expect(clippy::many_single_char_names, reason = "the names follow RFC 8439")]
fn quarter_round(x: &mut [__m256i; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = _mm256_add_epi32(x[a], x[b]);
    x[d] = rotate_16(_mm256_xor_si256(x[d], x[a]));
    x[c] = _mm256_add_epi32(x[c], x[d]);
    x[b] = rotate::<12, 20>(_mm256_xor_si256(x[b], x[c]));
    x[a] = _mm256_add_epi32(x[a], x[b]);
    x[d] = rotate_8(_mm256_xor_si256(x[d], x[a]));
    x[c] = _mm256_add_epi32(x[c], x[d]);
    x[b] = rotate::<7, 25>(_mm256_xor_si256(x[b], x[c]));
}

/// Rotates every lane left by a bit count that is not a whole number of bytes.
///
/// The second parameter must equal 32 minus the first.
#[inline]
#[target_feature(enable = "avx2")]
fn rotate<const LEFT: i32, const RIGHT: i32>(v: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32::<LEFT>(v), _mm256_srli_epi32::<RIGHT>(v))
}

/// Rotates every lane left by 16 bits with one byte shuffle.
#[inline]
#[target_feature(enable = "avx2")]
fn rotate_16(v: __m256i) -> __m256i {
    // Byte k of a lane comes from byte (k + 2) mod 4: the two halves swap.
    let order = _mm256_setr_epi8(
        2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9,
        14, 15, 12, 13,
    );
    _mm256_shuffle_epi8(v, order)
}

/// Rotates every lane left by 8 bits with one byte shuffle.
#[inline]
#[target_feature(enable = "avx2")]
fn rotate_8(v: __m256i) -> __m256i {
    // Byte k of a lane comes from byte (k + 3) mod 4: the top byte wraps to the bottom.
    let order = _mm256_setr_epi8(
        3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10,
        15, 12, 13, 14,
    );
    _mm256_shuffle_epi8(v, order)
}

/// Transposes eight registers of eight 32-bit lanes.
///
/// # Algorithm
///
/// Rows r0..r7 hold word i of blocks 0..7; the output holds blocks.
///
/// ```text
/// unpack 32 : [r0.0 r1.0 r0.1 r1.1 | r0.4 r1.4 r0.5 r1.5]   pairs of rows
/// unpack 64 : [r0.0 r1.0 r2.0 r3.0 | r0.4 r1.4 r2.4 r3.4]   quads of rows
/// permute   : [r0.0 .. r3.0 | r4.0 .. r7.0]                 block 0 whole
/// ```
#[inline]
#[target_feature(enable = "avx2")]
fn transpose(rows: &[__m256i]) -> [__m256i; 8] {
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

    // Stage 3: join the 128-bit halves; selector 0x20 takes both lows, 0x31 both highs.
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
fn xor_into(data: &mut [u8; 32], keystream: __m256i) {
    let pointer = data.as_mut_ptr().cast::<__m256i>();
    // SAFETY: the pointer covers exactly 32 writable bytes, and the unaligned forms accept any address.
    unsafe {
        let mixed = _mm256_xor_si256(_mm256_loadu_si256(pointer), keystream);
        _mm256_storeu_si256(pointer, mixed);
    }
}
