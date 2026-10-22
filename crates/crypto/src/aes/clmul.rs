//! GHASH with the x86_64 PCLMULQDQ carry-less multiplier.

use std::arch::x86_64::{
    __m128i, _mm_and_si128, _mm_clmulepi64_si128, _mm_loadu_si128, _mm_or_si128, _mm_set_epi64x,
    _mm_set1_epi8, _mm_shuffle_epi8, _mm_shuffle_epi32, _mm_slli_si128, _mm_srli_epi16,
    _mm_srli_si128, _mm_storeu_si128, _mm_xor_si128,
};

use super::BLOCK_LEN;

/// Bit reversal of each nibble value, placed in the high nibble of the byte.
const REVERSE_INTO_HIGH: [u8; 16] = [
    0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
];

/// Bit reversal of each nibble value, placed in the low nibble of the byte.
const REVERSE_INTO_LOW: [u8; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];

/// The reduction constant x^7 + x^2 + x + 1, since x^128 = that modulo the GCM polynomial.
const POLY: i64 = 0x87;

/// A running GHASH value and the powers of its key, held in vector registers.
///
/// Values are in the natural bit order of the portable path, so both paths share state.
#[derive(Clone, Copy, Debug)]
pub(super) struct ClmulGhash {
    /// H, H^2, H^3, H^4.
    powers: [__m128i; 4],
    /// The running value Y.
    running: __m128i,
}

impl ClmulGhash {
    /// Absorbs whole blocks into the running value and returns the new value.
    ///
    /// Loading, absorbing, and storing share one target-feature boundary.
    /// The powers therefore stay in registers for the whole call.
    #[target_feature(enable = "pclmulqdq,ssse3,sse2")]
    pub(super) fn update(powers: &[u128; 4], acc: u128, blocks: &[[u8; BLOCK_LEN]]) -> u128 {
        // Move H^1..H^4 and the running value into registers, in the natural bit order.
        let mut ghash = Self {
            powers: powers.map(|power| Self::from_u128(power)),
            running: Self::from_u128(acc),
        };
        ghash.absorb(blocks);
        Self::to_u128(ghash.running)
    }

    /// Absorbs whole blocks into the running value.
    ///
    /// # Algorithm
    ///
    /// Four blocks share one reduction, by Horner's rule unrolled four times.
    ///
    /// ```text
    /// Y' = (Y ^ X1) H^4 ^ X2 H^3 ^ X3 H^2 ^ X4 H
    /// ```
    ///
    /// The four products accumulate unreduced in 256 bits, then reduce once.
    #[inline]
    #[target_feature(enable = "pclmulqdq,ssse3,sse2")]
    fn absorb(&mut self, blocks: &[[u8; BLOCK_LEN]]) {
        let [h1, h2, h3, h4] = self.powers;

        // Four blocks per reduction.
        let (groups, rest) = blocks.as_chunks::<4>();
        for group in groups {
            let natural = group.map(|block| Self::to_natural(&block));
            let mut sum = WideProduct::new(_mm_xor_si128(self.running, natural[0]), h4);
            for (block, power) in natural[1..].iter().zip([h3, h2, h1]) {
                sum.accumulate(WideProduct::new(*block, power));
            }
            self.running = sum.reduce();
        }

        // The remaining blocks one at a time.
        for block in rest {
            let x = _mm_xor_si128(self.running, Self::to_natural(block));
            self.running = WideProduct::new(x, h1).reduce();
        }
    }

    /// Loads a GCM block and reverses the bits of each byte, giving the natural bit order.
    ///
    /// A little-endian load already puts byte k at bits 8k..8k+7.
    /// GCM stores x^(8k) in the top bit of byte k, so only the bits within each byte need reversing.
    #[inline]
    #[target_feature(enable = "ssse3,sse2")]
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the unaligned load accepts any address"
    )]
    fn to_natural(block: &[u8; BLOCK_LEN]) -> __m128i {
        // SAFETY: each pointer covers 16 readable bytes, and unaligned loads accept any address.
        let (value, into_high, into_low) = unsafe {
            (
                _mm_loadu_si128(block.as_ptr().cast::<__m128i>()),
                _mm_loadu_si128(REVERSE_INTO_HIGH.as_ptr().cast::<__m128i>()),
                _mm_loadu_si128(REVERSE_INTO_LOW.as_ptr().cast::<__m128i>()),
            )
        };

        // Look up each nibble's reversal: the low nibble lands high, the high nibble lands low.
        let nibble = _mm_set1_epi8(0x0f);
        let low_nibbles = _mm_and_si128(value, nibble);
        let high_nibbles = _mm_and_si128(_mm_srli_epi16::<4>(value), nibble);
        _mm_or_si128(
            _mm_shuffle_epi8(into_high, low_nibbles),
            _mm_shuffle_epi8(into_low, high_nibbles),
        )
    }

    /// Moves a 128-bit integer into a register, bit i to bit i.
    #[inline]
    #[target_feature(enable = "sse2")]
    fn from_u128(value: u128) -> __m128i {
        _mm_set_epi64x(
            ((value >> 64) as u64).cast_signed(),
            (value as u64).cast_signed(),
        )
    }

    /// Moves a register into a 128-bit integer, bit i to bit i.
    #[inline]
    #[target_feature(enable = "sse2")]
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the unaligned store accepts any address"
    )]
    fn to_u128(value: __m128i) -> u128 {
        let mut bytes = [0_u8; 16];
        // SAFETY: the pointer covers 16 writable bytes, and unaligned stores accept any address.
        unsafe {
            _mm_storeu_si128(bytes.as_mut_ptr().cast::<__m128i>(), value);
        }
        u128::from_le_bytes(bytes)
    }
}

/// A 128 x 128 carry-less product held as its three unreduced Karatsuba parts.
///
/// ```text
/// low    = a0 b0
/// high   = a1 b1
/// middle = (a0 ^ a1)(b0 ^ b1)
/// ```
///
/// Products under one reduction add part by part, so four blocks share one reduction.
#[derive(Clone, Copy, Debug)]
struct WideProduct {
    /// The product of the high halves.
    high: __m128i,
    /// The product of the folded halves.
    middle: __m128i,
    /// The product of the low halves.
    low: __m128i,
}

impl WideProduct {
    /// The three partial products of two operands.
    ///
    /// The selector of PCLMULQDQ picks a 64-bit half of each operand: 0x00 low-low, 0x11 high-high.
    #[inline]
    #[target_feature(enable = "pclmulqdq,sse2")]
    fn new(a: __m128i, b: __m128i) -> Self {
        // The two outer products need no preprocessing.
        let low = _mm_clmulepi64_si128::<0x00>(a, b);
        let high = _mm_clmulepi64_si128::<0x11>(a, b);

        // Shuffle 0x4e swaps the two 64-bit halves, so the XOR holds a0 ^ a1 in both.
        let a_folded = _mm_xor_si128(a, _mm_shuffle_epi32::<0x4e>(a));
        let b_folded = _mm_xor_si128(b, _mm_shuffle_epi32::<0x4e>(b));
        let middle = _mm_clmulepi64_si128::<0x00>(a_folded, b_folded);
        Self { high, middle, low }
    }

    /// Adds another product, part by part, without reducing.
    #[inline]
    #[target_feature(enable = "sse2")]
    fn accumulate(&mut self, other: Self) {
        // Addition in characteristic 2 is XOR, and it commutes with the later reduction.
        self.high = _mm_xor_si128(self.high, other.high);
        self.middle = _mm_xor_si128(self.middle, other.middle);
        self.low = _mm_xor_si128(self.low, other.low);
    }

    /// Combines the parts and reduces modulo x^128 + x^7 + x^2 + x + 1.
    ///
    /// # Algorithm
    ///
    /// The 256-bit product has four 64-bit words r3 r2 r1 r0.
    ///
    /// ```text
    /// fold r3 : r3 x^192 = (r3 * 0x87) x^64     -> XOR into r2 r1
    /// fold r2 : r2 x^128 = r2 * 0x87            -> XOR into r1 r0
    /// ```
    ///
    /// Each fold product is at most 71 bits, so two folds clear everything above bit 127.
    #[inline]
    #[target_feature(enable = "pclmulqdq,sse2")]
    fn reduce(self) -> __m128i {
        let Self { high, middle, low } = self;

        // Karatsuba: the true middle term is middle ^ low ^ high, straddling the two halves.
        let middle = _mm_xor_si128(middle, _mm_xor_si128(low, high));
        let mut low = _mm_xor_si128(low, _mm_slli_si128::<8>(middle));
        let mut high = _mm_xor_si128(high, _mm_srli_si128::<8>(middle));

        // Fold r3, the high word of the high half, down by 128 bits.
        let poly = _mm_set_epi64x(0, POLY);
        let t = _mm_clmulepi64_si128::<0x01>(high, poly);
        low = _mm_xor_si128(low, _mm_slli_si128::<8>(t));
        high = _mm_xor_si128(high, _mm_srli_si128::<8>(t));

        // Fold r2, now the only word left above bit 127.
        let u = _mm_clmulepi64_si128::<0x00>(high, poly);
        _mm_xor_si128(low, u)
    }
}
