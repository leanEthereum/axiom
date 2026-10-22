//! Arithmetic modulo p = 2^255 - 19 in five 51-bit limbs.

use std::array;

use crate::ct::Mask;

/// The low 51 bits of a limb.
const MASK_51: u64 = (1 << 51) - 1;

/// An element of GF(2^255 - 19).
///
/// # Overview
///
/// The value is sum_i limbs[i] * 2^(51 i), with five limbs covering 255 bits.
///
/// ```text
///   bit 255     204       153       102        51         0
///        | l4:51 | l3:51  | l2:51   | l1:51    | l0:51    |
/// ```
///
/// # Invariants
///
/// Every operation returns limbs below 2^52.
/// The value itself may exceed p; only the byte encoding is canonical.
#[derive(Clone, Copy, Debug)]
pub(super) struct FieldElement([u64; 5]);

impl FieldElement {
    /// Zero.
    pub(super) const ZERO: Self = Self([0; 5]);

    /// One.
    pub(super) const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// Decodes 32 little-endian bytes, ignoring the top bit, per RFC 7748, section 5.
    ///
    /// Values in [p, 2^255) are accepted and reduce on use, as the RFC requires.
    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Self {
        let (words, _) = bytes.as_chunks::<8>();
        let w: [u64; 4] = array::from_fn(|i| u64::from_le_bytes(words[i]));

        // Cut the 255 bits at multiples of 51.
        //
        //     limb 0 : bits   0..51  from word 0
        //     limb 1 : bits  51..102 straddles words 0 and 1
        //     limb 4 : bits 204..255 from word 3, dropping bit 255
        Self([
            w[0] & MASK_51,
            ((w[0] >> 51) | (w[1] << 13)) & MASK_51,
            ((w[1] >> 38) | (w[2] << 26)) & MASK_51,
            ((w[2] >> 25) | (w[3] << 39)) & MASK_51,
            (w[3] >> 12) & MASK_51,
        ])
    }

    /// Encodes the unique representative in [0, p) as 32 little-endian bytes.
    pub(super) fn to_bytes(self) -> [u8; 32] {
        // Phase 1: carry fully so each limb is below 2^51 and the value below 2^255 + small.
        let mut h = self.carried().0;

        // Phase 2: decide h >= p without branching.
        //
        // h >= p exactly when h + 19 reaches 2^255.
        // Ripple the carry of h + 19 through the limbs and read it out of the top.
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;

        // Phase 3: subtract q p by adding 19 q and dropping bit 255.
        h[0] += 19 * q;
        for i in 0..4 {
            h[i + 1] += h[i] >> 51;
            h[i] &= MASK_51;
        }
        h[4] &= MASK_51;

        // Phase 4: pack the five 51-bit limbs back into four 64-bit words.
        let words = [
            h[0] | (h[1] << 51),
            (h[1] >> 13) | (h[2] << 38),
            (h[2] >> 26) | (h[3] << 25),
            (h[3] >> 39) | (h[4] << 12),
        ];
        let mut out = [0_u8; 32];
        let (chunks, _) = out.as_chunks_mut::<8>();
        for (chunk, word) in chunks.iter_mut().zip(words) {
            *chunk = word.to_le_bytes();
        }
        out
    }

    /// The sum, carried back under 2^52 per limb.
    pub(super) fn add(self, other: Self) -> Self {
        let mut sum = self.0;
        for (limb, b) in sum.iter_mut().zip(other.0) {
            *limb += b;
        }
        Self(sum).carried()
    }

    /// The difference, carried back under 2^52 per limb.
    pub(super) fn sub(self, other: Self) -> Self {
        // Add 4p first so no limb underflows.
        //
        // 4p in limbs is (2^53 - 76, 2^53 - 4, 2^53 - 4, 2^53 - 4, 2^53 - 4).
        // Each exceeds 2^52, the largest limb the other operand may hold.
        let four_p = [
            (1 << 53) - 76,
            (1 << 53) - 4,
            (1 << 53) - 4,
            (1 << 53) - 4,
            (1 << 53) - 4,
        ];
        let mut difference = self.0;
        for ((limb, b), bias) in difference.iter_mut().zip(other.0).zip(four_p) {
            *limb = *limb + bias - b;
        }
        Self(difference).carried()
    }

    /// The product.
    pub(super) fn mul(self, other: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = other.0;

        // A product of weight 2^(51 k) with k >= 5 wraps to 19 times weight 2^(51 (k - 5)).
        // The reason: 2^255 = 19 mod p.
        let (b1_19, b2_19, b3_19, b4_19) = (b1 * 19, b2 * 19, b3 * 19, b4 * 19);
        let m = |x: u64, y: u64| u128::from(x) * u128::from(y);

        // Schoolbook columns.
        //
        // Limbs below 2^52 and factors of 19 keep each sum below 5 * 2^52 * 2^57 < 2^112.
        let c0 = m(a0, b0) + m(a1, b4_19) + m(a2, b3_19) + m(a3, b2_19) + m(a4, b1_19);
        let c1 = m(a0, b1) + m(a1, b0) + m(a2, b4_19) + m(a3, b3_19) + m(a4, b2_19);
        let c2 = m(a0, b2) + m(a1, b1) + m(a2, b0) + m(a3, b4_19) + m(a4, b3_19);
        let c3 = m(a0, b3) + m(a1, b2) + m(a2, b1) + m(a3, b0) + m(a4, b4_19);
        let c4 = m(a0, b4) + m(a1, b3) + m(a2, b2) + m(a3, b1) + m(a4, b0);

        Self::carry_wide([c0, c1, c2, c3, c4])
    }

    /// The square.
    pub(super) fn square(self) -> Self {
        self.mul(self)
    }

    /// The square taken k times in a row.
    pub(super) fn square_times(self, k: u32) -> Self {
        let mut x = self;
        for _ in 0..k {
            x = x.square();
        }
        x
    }

    /// The product with a small constant below 2^25.
    pub(super) fn mul_small(self, small: u32) -> Self {
        let mut wide = [0_u128; 5];
        for (column, limb) in wide.iter_mut().zip(self.0) {
            *column = u128::from(limb) * u128::from(small);
        }
        Self::carry_wide(wide)
    }

    /// The inverse, by Fermat: a^(p - 2), and zero for zero.
    ///
    /// # Algorithm
    ///
    /// The exponent p - 2 = 2^255 - 21 has a fixed addition chain, as in curve25519 ref10.
    /// The chain is public, so the timing does not depend on the input.
    ///
    /// ```text
    /// z^(2^5 - 1) -> z^(2^10 - 1) -> ... -> z^(2^250 - 1)
    /// z^(2^255 - 21) = (z^(2^250 - 1))^(2^5) * z^11
    /// ```
    pub(super) fn invert(self) -> Self {
        let z = self;
        let z2 = z.square();
        let z9 = z2.square_times(2).mul(z);
        let z11 = z9.mul(z2);
        let z_5_0 = z11.square().mul(z9);
        let z_10_0 = z_5_0.square_times(5).mul(z_5_0);
        let z_20_0 = z_10_0.square_times(10).mul(z_10_0);
        let z_40_0 = z_20_0.square_times(20).mul(z_20_0);
        let z_50_0 = z_40_0.square_times(10).mul(z_10_0);
        let z_100_0 = z_50_0.square_times(50).mul(z_50_0);
        let z_200_0 = z_100_0.square_times(100).mul(z_100_0);
        let z_250_0 = z_200_0.square_times(50).mul(z_50_0);
        z_250_0.square_times(5).mul(z11)
    }

    /// Swaps the two elements when the condition holds, without branching.
    pub(super) fn conditional_swap(a: &mut Self, b: &mut Self, swap: Mask) {
        for (x, y) in a.0.iter_mut().zip(b.0.iter_mut()) {
            // Masked XOR swap: the difference flows both ways only under the mask.
            let t = swap.word() & (*x ^ *y);
            *x ^= t;
            *y ^= t;
        }
    }

    /// Carries every limb into the next, folding the top carry back with a factor of 19.
    fn carried(self) -> Self {
        let mut h = self.0;
        let mut carry = 0;
        for limb in &mut h {
            *limb += carry;
            carry = *limb >> 51;
            *limb &= MASK_51;
        }
        // 2^255 = 19 mod p; the folded carry is small, so limb 0 stays below 2^52.
        h[0] += carry * 19;
        Self(h)
    }

    /// Reduces five 128-bit columns to limbs below 2^52.
    fn carry_wide(c: [u128; 5]) -> Self {
        let mut h = [0_u64; 5];
        let mut carry = 0_u128;
        for (limb, column) in h.iter_mut().zip(c) {
            let value = column + carry;
            *limb = (value as u64) & MASK_51;
            carry = value >> 51;
        }

        // The top carry is below 2^62; times 19 it still fits a 64-bit word plus limb 0.
        let folded = u128::from(h[0]) + carry * 19;
        h[0] = (folded as u64) & MASK_51;
        h[1] += (folded >> 51) as u64;
        Self(h)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The 32-byte encoding of p - 1, the largest canonical value.
    fn p_minus_one() -> [u8; 32] {
        let mut bytes = [0xff_u8; 32];
        bytes[0] = 0xec;
        bytes[31] = 0x7f;
        bytes
    }

    #[test]
    fn non_canonical_inputs_reduce() {
        // p itself decodes and re-encodes as 0.
        let mut p = p_minus_one();
        p[0] += 1;
        assert_eq!(FieldElement::from_bytes(&p).to_bytes(), [0; 32]);

        // p + 1 re-encodes as 1.
        p[0] += 1;
        let mut one = [0_u8; 32];
        one[0] = 1;
        assert_eq!(FieldElement::from_bytes(&p).to_bytes(), one);

        // The top bit is ignored: 2^255 + 5 decodes as 5.
        let mut high = [0_u8; 32];
        high[0] = 5;
        high[31] = 0x80;
        let mut five = [0_u8; 32];
        five[0] = 5;
        assert_eq!(FieldElement::from_bytes(&high).to_bytes(), five);
    }

    #[test]
    fn minus_one_squares_to_one() {
        // (p - 1)^2 = 1 exercises the largest limbs through multiplication and encoding.
        let minus_one = FieldElement::from_bytes(&p_minus_one());
        assert_eq!(minus_one.square().to_bytes(), FieldElement::ONE.to_bytes());

        // 0 - 1 = p - 1 exercises the bias in subtraction.
        assert_eq!(
            FieldElement::ZERO.sub(FieldElement::ONE).to_bytes(),
            p_minus_one()
        );
    }

    proptest! {
        #[test]
        fn canonical_bytes_round_trip(mut bytes in any::<[u8; 32]>()) {
            // Any value below 2^255 - 19 survives decode then encode.
            bytes[31] &= 0x7f;
            let encoded = FieldElement::from_bytes(&bytes).to_bytes();
            let value_below_p = bytes[31] < 0x7f || bytes[1..31].iter().any(|&b| b != 0xff) || bytes[0] < 0xed;
            if value_below_p {
                prop_assert_eq!(encoded, bytes);
            }
        }

        #[test]
        fn field_laws(a in any::<[u8; 32]>(), b in any::<[u8; 32]>(), c in any::<[u8; 32]>()) {
            let (a, b, c) = (FieldElement::from_bytes(&a), FieldElement::from_bytes(&b), FieldElement::from_bytes(&c));

            // Distributivity ties the multiplier to the adder: a (b + c) = a b + a c.
            prop_assert_eq!(a.mul(b.add(c)).to_bytes(), a.mul(b).add(a.mul(c)).to_bytes());

            // Subtraction undoes addition.
            prop_assert_eq!(a.add(b).sub(b).to_bytes(), a.to_bytes());

            // Small multiplication equals multiplication by the encoded constant.
            let mut k = [0_u8; 32];
            k[..4].copy_from_slice(&121_665_u32.to_le_bytes());
            prop_assert_eq!(a.mul_small(121_665).to_bytes(), a.mul(FieldElement::from_bytes(&k)).to_bytes());

            // Every non-zero element has an inverse.
            if a.to_bytes() != [0; 32] {
                prop_assert_eq!(a.mul(a.invert()).to_bytes(), FieldElement::ONE.to_bytes());
            }
        }
    }
}
