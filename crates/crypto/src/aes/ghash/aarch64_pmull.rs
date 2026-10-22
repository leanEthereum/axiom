//! GHASH with the ARMv8 PMULL carry-less multiplier.
//!
//! # Overview
//!
//! PMULL returns the exact 128-bit carry-less product of two 64-bit polynomials.
//! Karatsuba builds the 256-bit product from three of them, and two folds reduce it.
//! The result equals the portable field product bit for bit.
//!
//! PMULL is a data-independent-timing instruction in the Arm architecture.
//! No branch or address depends on H or the data.

use std::arch::aarch64::{
    uint64x2_t, vcombine_u64, vcreate_u64, vdupq_n_u64, veorq_u64, vextq_u64, vgetq_lane_u64,
    vmull_high_p64, vmull_p64, vrbitq_u8, vreinterpretq_p64_u64, vreinterpretq_u8_u64,
    vreinterpretq_u64_p128, vreinterpretq_u64_u8,
};

use crate::aes::BLOCK_LEN;

/// The reduction constant x^7 + x^2 + x + 1, since x^128 = that modulo the GCM polynomial.
const POLY: u64 = 0x87;

/// A running GHASH value and the powers of its key, held in vector registers.
///
/// Values are in the natural bit order of the portable path, so both paths share state.
#[derive(Clone, Copy, Debug)]
pub(super) struct PmullGhash {
    /// H, H^2, H^3, H^4.
    powers: [uint64x2_t; 4],
    /// The running value Y.
    running: uint64x2_t,
}

impl PmullGhash {
    /// Absorbs whole blocks into the running value and returns the new value.
    ///
    /// Loading, absorbing, and storing share one target-feature boundary.
    /// The powers therefore stay in registers for the whole call.
    #[target_feature(enable = "neon,aes")]
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
    #[target_feature(enable = "neon,aes")]
    fn absorb(&mut self, blocks: &[[u8; BLOCK_LEN]]) {
        let [h1, h2, h3, h4] = self.powers;

        // Four blocks per reduction.
        let (groups, rest) = blocks.as_chunks::<4>();
        for group in groups {
            let natural = group.map(|block| Self::to_natural(&block));
            let mut sum = WideProduct::new(veorq_u64(self.running, natural[0]), h4);
            for (block, power) in natural[1..].iter().zip([h3, h2, h1]) {
                sum.accumulate(WideProduct::new(*block, power));
            }
            self.running = sum.reduce();
        }

        // The remaining blocks one at a time.
        for block in rest {
            let x = veorq_u64(self.running, Self::to_natural(block));
            self.running = WideProduct::new(x, h1).reduce();
        }
    }

    /// Reads a GCM block and reverses the bits of each byte, giving the natural bit order.
    ///
    /// Read as a little-endian integer, byte k sits at bits 8k..8k+7.
    /// GCM stores x^(8k) in the top bit of byte k, so only the bits within each byte need reversing.
    /// RBIT reverses each byte in place, wherever the byte sits in the register.
    #[inline]
    #[target_feature(enable = "neon")]
    fn to_natural(block: &[u8; BLOCK_LEN]) -> uint64x2_t {
        let value = Self::from_u128(u128::from_le_bytes(*block));
        vreinterpretq_u64_u8(vrbitq_u8(vreinterpretq_u8_u64(value)))
    }

    /// Moves a 128-bit integer into a register: the low half to lane 0, the high half to lane 1.
    #[inline]
    #[target_feature(enable = "neon")]
    fn from_u128(value: u128) -> uint64x2_t {
        vcombine_u64(vcreate_u64(value as u64), vcreate_u64((value >> 64) as u64))
    }

    /// Moves a register into a 128-bit integer: lane 0 to the low half, lane 1 to the high half.
    #[inline]
    #[target_feature(enable = "neon")]
    fn to_u128(value: uint64x2_t) -> u128 {
        let low = vgetq_lane_u64::<0>(value);
        let high = vgetq_lane_u64::<1>(value);
        (u128::from(high) << 64) | u128::from(low)
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
    high: uint64x2_t,
    /// The product of the folded halves.
    middle: uint64x2_t,
    /// The product of the low halves.
    low: uint64x2_t,
}

impl WideProduct {
    /// The three partial products of two operands.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    fn new(a: uint64x2_t, b: uint64x2_t) -> Self {
        // The two outer products need no preprocessing.
        // PMULL2 multiplies the high lanes directly.
        let low = Self::multiply_low(a, b);
        let high = vreinterpretq_u64_p128(vmull_high_p64(
            vreinterpretq_p64_u64(a),
            vreinterpretq_p64_u64(b),
        ));

        // Rotating by one lane swaps the halves, so the XOR holds a0 ^ a1 in lane 0.
        let a_folded = veorq_u64(a, vextq_u64::<1>(a, a));
        let b_folded = veorq_u64(b, vextq_u64::<1>(b, b));
        let middle = Self::multiply_low(a_folded, b_folded);
        Self { high, middle, low }
    }

    /// The carry-less product of the low lanes of two registers.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    fn multiply_low(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<0>(a), vgetq_lane_u64::<0>(b)))
    }

    /// Adds another product, part by part, without reducing.
    #[inline]
    #[target_feature(enable = "neon")]
    fn accumulate(&mut self, other: Self) {
        // Addition in characteristic 2 is XOR, and it commutes with the later reduction.
        self.high = veorq_u64(self.high, other.high);
        self.middle = veorq_u64(self.middle, other.middle);
        self.low = veorq_u64(self.low, other.low);
    }

    /// Combines the parts and reduces modulo x^128 + x^7 + x^2 + x + 1.
    ///
    /// # Algorithm
    ///
    /// The 256-bit product has four 64-bit words r3 r2 r1 r0.
    ///
    /// ```text
    /// r3 x^192 = (r3 * 0x87) x^64     folds into r2 r1
    /// r2 x^128 = r2 * 0x87            folds into r1 r0
    /// ```
    ///
    /// Each fold product is at most 71 bits, so two folds clear everything above bit 127.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    fn reduce(self) -> uint64x2_t {
        let Self { high, middle, low } = self;
        let zero = vdupq_n_u64(0);

        // Karatsuba: the true middle term is middle ^ low ^ high, straddling the two halves.
        //
        //     [0, m0] shifts the middle up one word; [m1, 0] shifts it down one word.
        let middle = veorq_u64(middle, veorq_u64(low, high));
        let low = veorq_u64(low, vextq_u64::<1>(zero, middle));
        let high = veorq_u64(high, vextq_u64::<1>(middle, zero));

        // Fold r3, the high word of the high half, down by 128 bits.
        let t = vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<1>(high), POLY));
        let low = veorq_u64(low, vextq_u64::<1>(zero, t));
        let high = veorq_u64(high, vextq_u64::<1>(t, zero));

        // Fold r2, now the only word left above bit 127.
        let u = vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<0>(high), POLY));
        veorq_u64(low, u)
    }
}
