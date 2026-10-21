//! The base field F_p of BLS12-381, where p is a 381-bit prime.
//!
//! # Overview
//!
//! Elements live in Montgomery form: the value a is stored as a * R mod p, with R = 2^384.
//! Multiplication then needs no division by p, only shifts by whole limbs.
//!
//! ```text
//!     stored(a) * stored(b) * R^{-1} = (a R)(b R) R^{-1} = (a b) R = stored(a b)
//! ```
//!
//! Every arithmetic routine runs in time independent of its operands.
//! Inversion and square roots raise to fixed public exponents, so they do too.

use std::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use crate::arithmetic::{adc, limbs_from_be_bytes, limbs_to_be_bytes, mac, mask, sbb};

/// The field modulus p, as little-endian 64-bit limbs.
///
/// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab.
const MODULUS: [u64; 6] = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

/// The constant -p^{-1} mod 2^64.
///
/// Montgomery reduction multiplies the low limb by it to find the multiple of p that clears that limb.
const INV: u64 = 0x89f3_fffc_fffc_fffd;

/// The value R = 2^384 mod p, which is the Montgomery form of one.
const R: [u64; 6] = [
    0x7609_0000_0002_fffd,
    0xebf4_000b_c40c_0002,
    0x5f48_9857_53c7_58ba,
    0x77ce_5853_7052_5745,
    0x5c07_1a97_a256_ec6d,
    0x15f6_5ec3_fa80_e493,
];

/// The value R^2 mod p.
///
/// A Montgomery product with it maps a plain integer a to its Montgomery form a * R.
const R2: [u64; 6] = [
    0xf4df_1f34_1c34_1746,
    0x0a76_e6a6_09d1_04f1,
    0x8de5_476c_4c95_b6d5,
    0x67eb_88a9_939d_83c0,
    0x9a79_3e85_b519_952d,
    0x1198_8fe5_92ca_e3aa,
];

/// The value 2^256 * R^2 mod p.
///
/// A Montgomery product with it maps the high half h of a 512-bit integer to (h * 2^256) * R.
const WIDE_SHIFT: [u64; 6] = [
    0xfb73_eaea_d26e_be58,
    0x861c_2369_3de6_a351,
    0x76e5_bc3f_f951_c543,
    0xcc08_68ce_6a76_590c,
    0xf0a8_5a3f_3544_6d0b,
    0x0010_a8c1_a49a_064f,
];

/// The exponent p - 2.
///
/// By Fermat's little theorem a^{p-2} = a^{-1} for every nonzero a.
const P_MINUS_2: [u64; 6] = [
    0xb9fe_ffff_ffff_aaa9,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

/// The exponent (p + 1) / 4.
///
/// Since p = 3 mod 4, a^{(p+1)/4} squares to a whenever a is a square.
const SQRT_EXPONENT: [u64; 6] = [
    0xee7f_bfff_ffff_eaab,
    0x07aa_ffff_ac54_ffff,
    0xd9cc_34a8_3dac_3d89,
    0xd91d_d2e1_3ce1_44af,
    0x92c6_e9ed_90d2_eb35,
    0x0680_447a_8e5f_f9a6,
];

/// The value (p - 1) / 2, the largest element that is not lexicographically largest.
const HALF_MODULUS: [u64; 6] = [
    0xdcff_7fff_ffff_d555,
    0x0f55_ffff_58a9_ffff,
    0xb398_6950_7b58_7b12,
    0xb23b_a5c2_79c2_895f,
    0x258d_d3db_21a5_d66b,
    0x0d00_88f5_1cbf_f34d,
];

/// Number of bytes in the canonical big-endian encoding of an element.
pub const FP_BYTES: usize = 48;

/// An element of the base field F_p.
///
/// The limbs hold the Montgomery form, always fully reduced below p.
/// Equality of limbs is therefore equality of field elements.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Fp(pub(crate) [u64; 6]);

impl Fp {
    /// The additive identity.
    pub const ZERO: Self = Self([0; 6]);

    /// The multiplicative identity.
    pub const ONE: Self = Self(R);

    /// Wraps limbs that already hold a reduced Montgomery form.
    pub(crate) const fn from_montgomery(limbs: [u64; 6]) -> Self {
        Self(limbs)
    }

    /// Embeds a small integer into the field.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        // value < 2^64 < p, so it is already reduced; one product with R^2 moves it to Montgomery form.
        Self(Self::montgomery_mul(&[value, 0, 0, 0, 0, 0], &R2))
    }

    /// Decodes a canonical big-endian encoding.
    ///
    /// # Returns
    ///
    /// The element, or nothing when the integer is not below p.
    #[must_use]
    pub fn from_bytes_be(bytes: &[u8; FP_BYTES]) -> Option<Self> {
        let limbs: [u64; 6] = limbs_from_be_bytes(bytes);

        // Subtract p and watch the final borrow.
        //
        //     limbs <  p: the subtraction underflows, the borrow mask is all ones
        //     limbs >= p: no underflow, the encoding is not canonical
        let mut borrow = 0;
        for (limb, modulus) in limbs.iter().zip(MODULUS) {
            (_, borrow) = sbb(*limb, modulus, borrow);
        }
        if borrow == 0 {
            return None;
        }

        // The integer is reduced, so one product with R^2 yields its Montgomery form.
        Some(Self(Self::montgomery_mul(&limbs, &R2)))
    }

    /// Encodes the element as 48 canonical big-endian bytes.
    #[must_use]
    pub fn to_bytes_be(&self) -> [u8; FP_BYTES] {
        let mut out = [0; FP_BYTES];
        limbs_to_be_bytes(&self.to_canonical(), &mut out);
        out
    }

    /// Reduces a 64-byte big-endian integer modulo p.
    ///
    /// This is the reduction RFC 9380 section 5.2 applies to each chunk of expanded message.
    /// With 512 input bits the result is within 2^{-128} of uniform.
    pub(crate) fn from_bytes_wide_be(bytes: &[u8; 64]) -> Self {
        // Split the 512-bit integer into two 256-bit halves, both below p.
        //
        //     n = high * 2^256 + low
        let high: [u64; 4] = limbs_from_be_bytes(&bytes[..32]);
        let low: [u64; 4] = limbs_from_be_bytes(&bytes[32..]);
        let high = [high[0], high[1], high[2], high[3], 0, 0];
        let low = [low[0], low[1], low[2], low[3], 0, 0];

        // Map each half to Montgomery form, scaling the high half by 2^256 on the way.
        //
        //     low  * R^2 * R^{-1}            = low * R
        //     high * 2^256 R^2 * R^{-1}      = high * 2^256 * R
        let low = Self(Self::montgomery_mul(&low, &R2));
        let high = Self(Self::montgomery_mul(&high, &WIDE_SHIFT));
        low + high
    }

    /// Whether the element is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        // OR all limbs together so the check does not exit early.
        self.0.iter().fold(0, |acc, limb| acc | limb) == 0
    }

    /// Returns 2 * self.
    #[must_use]
    pub fn double(&self) -> Self {
        self + self
    }

    /// Returns self^2.
    #[must_use]
    pub fn square(&self) -> Self {
        Self(Self::montgomery_mul(&self.0, &self.0))
    }

    /// Raises the element to a power given as little-endian limbs.
    ///
    /// The running time depends on the exponent, never on the base.
    /// Use it only with public exponents.
    ///
    /// # Performance
    ///
    /// Fixed 4-bit windows: one product per four exponent bits instead of one per set bit.
    /// A 381-bit exponent costs about 384 squarings and 105 products, against 574 operations bit by bit.
    #[must_use]
    pub fn pow_vartime(&self, exponent: &[u64]) -> Self {
        // Phase 1: table[i] = self^i for every 4-bit digit i.
        let mut table = [Self::ONE; 16];
        for i in 1..16 {
            table[i] = table[i - 1] * self;
        }

        // Phase 2: left to right, four squarings then one table product per digit.
        let mut result = Self::ONE;
        for limb in exponent.iter().rev() {
            for shift in (0..64).step_by(4).rev() {
                result = result.square().square().square().square();
                let digit = (limb >> shift) & 0xf;
                if digit != 0 {
                    result *= table[usize::try_from(digit).unwrap_or(0)];
                }
            }
        }
        result
    }

    /// Computes the multiplicative inverse.
    ///
    /// # Returns
    ///
    /// The inverse, or nothing for zero.
    #[must_use]
    pub fn invert(&self) -> Option<Self> {
        // Fermat: a^{p-2} * a = a^{p-1} = 1.
        // The exponent is a public constant, so the timing does not depend on the base.
        let inverse = self.pow_vartime(&P_MINUS_2);
        (!self.is_zero()).then_some(inverse)
    }

    /// Computes a square root.
    ///
    /// # Returns
    ///
    /// A root, or nothing when the element is not a square.
    #[must_use]
    pub fn sqrt(&self) -> Option<Self> {
        // Since p = 3 mod 4, the candidate a^{(p+1)/4} squares to a^{(p+1)/2} = a * a^{(p-1)/2}.
        // Euler's criterion makes a^{(p-1)/2} equal to 1 exactly when a is a square.
        let candidate = self.pow_vartime(&SQRT_EXPONENT);
        (candidate.square() == *self).then_some(candidate)
    }

    /// Whether the element exceeds its own negation as an integer in [0, p).
    ///
    /// This is the sign rule of the ZCash point encoding.
    /// Zero is not lexicographically largest.
    #[must_use]
    pub fn is_lexicographically_largest(&self) -> bool {
        let canonical = self.to_canonical();

        // Compute canonical - ((p - 1) / 2) - 1 and keep only the borrow.
        //
        //     canonical >  (p - 1) / 2: no borrow, the element is the larger of the pair
        //     canonical <= (p - 1) / 2: borrow
        //
        // An incoming borrow mask of all ones subtracts the extra 1.
        let mut borrow = u64::MAX;
        for (limb, half) in canonical.iter().zip(HALF_MODULUS) {
            (_, borrow) = sbb(*limb, half, borrow);
        }
        borrow == 0
    }

    /// Whether the canonical integer is odd.
    ///
    /// This is the sgn0 function of RFC 9380 section 4.1 for a prime field.
    pub(crate) fn is_odd(&self) -> bool {
        self.to_canonical()[0] & 1 == 1
    }

    /// Picks the second element when the flag is set, the first otherwise.
    ///
    /// The selection reads both inputs in full and never branches on the flag.
    pub(crate) fn conditional_select(a: &Self, b: &Self, choice: bool) -> Self {
        let mask = mask(choice);
        let mut limbs = [0; 6];
        for ((out, a), b) in limbs.iter_mut().zip(a.0).zip(b.0) {
            *out = (a & !mask) | (b & mask);
        }
        Self(limbs)
    }

    /// Leaves Montgomery form and returns the canonical integer, as little-endian limbs.
    fn to_canonical(self) -> [u64; 6] {
        // A Montgomery product with plain 1 divides by R.
        //
        //     (a R) * 1 * R^{-1} = a
        Self::montgomery_mul(&self.0, &[1, 0, 0, 0, 0, 0])
    }

    /// Montgomery multiplication: returns a * b * R^{-1} mod p, fully reduced.
    ///
    /// # Algorithm
    ///
    /// Coarsely integrated operand scanning (CIOS), Koc, Acar, and Kaliski, 1996.
    /// Each round adds a * b_i, then adds the multiple m * p that zeroes the low limb, then shifts one limb.
    ///
    /// The top limb of p is below 2^63 - 1.
    /// That lets the running sum stay in six limbs without a seventh carry limb.
    /// This is the "no-carry" variant from the gnark-crypto field generator.
    ///
    /// Inputs must be below p.
    /// The result is below 2p before the final subtraction, and below p after it.
    fn montgomery_mul(a: &[u64; 6], b: &[u64; 6]) -> [u64; 6] {
        // One round per limb of b, written out so the compiler keeps t in registers.
        let t = Self::montgomery_round([0; 6], a, b[0]);
        let t = Self::montgomery_round(t, a, b[1]);
        let t = Self::montgomery_round(t, a, b[2]);
        let t = Self::montgomery_round(t, a, b[3]);
        let t = Self::montgomery_round(t, a, b[4]);
        let t = Self::montgomery_round(t, a, b[5]);
        Self::subtract_modulus_if_needed(t)
    }

    /// One CIOS round: returns (t + a * b_i + m * p) / 2^64 for the m that makes the division exact.
    #[inline(always)]
    #[allow(
        clippy::inline_always,
        reason = "six inlined rounds keep the accumulator in registers; a call per round spills it"
    )]
    fn montgomery_round(t: [u64; 6], a: &[u64; 6], b_i: u64) -> [u64; 6] {
        // Phase 1: fold in the lowest limb of a * b_i.
        let (t0, mut carry_ab) = mac(t[0], a[0], b_i, 0);

        // Phase 2: pick m so that t0 + m * p_0 = 0 mod 2^64.
        let m = t0.wrapping_mul(INV);
        let (_, mut carry_mp) = mac(t0, m, MODULUS[0], 0);

        // Phase 3: add the remaining limbs of a * b_i and m * p, shifting down one limb.
        //
        //     t_{j-1} <- t_j + a_j b_i + m p_j + carries
        let mut out = [0; 6];
        for j in 1..6 {
            let (tj, carry) = mac(t[j], a[j], b_i, carry_ab);
            carry_ab = carry;
            (out[j - 1], carry_mp) = mac(tj, m, MODULUS[j], carry_mp);
        }

        // Both carries fit in the top limb thanks to the spare bits of p.
        out[5] = carry_ab.wrapping_add(carry_mp);
        out
    }

    /// Returns a_0 b_0 + a_1 b_1 mod p with a single Montgomery reduction.
    ///
    /// # Algorithm
    ///
    /// Lazy reduction of a sum of products, eprint 2022/367 algorithm 2.
    /// Each round adds limb j of both left factors times the full right factors, then reduces once.
    ///
    /// ```text
    ///     separate : 2 products, 2 reductions, 1 modular addition
    ///     fused    : 2 products, 1 reduction
    /// ```
    ///
    /// Bound: the final value is (a_0 b_0 + a_1 b_1 + K p) / R with K < R.
    /// With p < R / 4 that is below 1.5 p, so one conditional subtraction reduces it.
    /// Intermediate values stay below 3p < 2^384, inside six limbs plus a carry limb.
    pub(crate) fn sum_of_products(lefts: [Self; 2], rights: [Self; 2]) -> Self {
        let mut acc = [0_u64; 6];
        for limb_index in 0..6 {
            // Phase 1: t = acc + sum_i lefts_i[limb_index] * rights_i, in seven limbs.
            let mut t = [acc[0], acc[1], acc[2], acc[3], acc[4], acc[5], 0];
            for (left, right) in lefts.iter().zip(&rights) {
                let mut carry = 0;
                for (limb, right_limb) in t.iter_mut().zip(right.0) {
                    (*limb, carry) = mac(*limb, left.0[limb_index], right_limb, carry);
                }
                t[6] = t[6].wrapping_add(carry);
            }

            // Phase 2: add m p with m chosen to clear the low limb, then shift down one limb.
            let m = t[0].wrapping_mul(INV);
            let (_, mut carry) = mac(t[0], m, MODULUS[0], 0);
            for i in 1..6 {
                (acc[i - 1], carry) = mac(t[i], m, MODULUS[i], carry);
            }
            acc[5] = t[6].wrapping_add(carry);
        }
        Self(Self::subtract_modulus_if_needed(acc))
    }

    /// Maps a value in [0, 2p) to [0, p) without branching.
    fn subtract_modulus_if_needed(value: [u64; 6]) -> [u64; 6] {
        // Tentatively subtract p.
        let mut reduced = [0; 6];
        let mut borrow = 0;
        for ((out, limb), modulus) in reduced.iter_mut().zip(value).zip(MODULUS) {
            (*out, borrow) = sbb(limb, modulus, borrow);
        }

        // A borrow means value < p already, so keep the original.
        let mut out = [0; 6];
        for ((out, reduced), original) in out.iter_mut().zip(reduced).zip(value) {
            *out = (reduced & !borrow) | (original & borrow);
        }
        out
    }
}

impl fmt::Debug for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Fp {
    /// Renders the canonical integer as 0x-prefixed big-endian hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.to_bytes_be() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Fp {
    /// Returns self + rhs mod p.
    #[inline]
    fn add_impl(&self, rhs: &Self) -> Self {
        // Both inputs are below p < 2^382, so the sum fits in six limbs with no carry out.
        let mut sum = [0; 6];
        let mut carry = 0;
        for ((out, a), b) in sum.iter_mut().zip(self.0).zip(rhs.0) {
            (*out, carry) = adc(a, b, carry);
        }
        // The sum is below 2p, so one conditional subtraction reduces it.
        Self(Self::subtract_modulus_if_needed(sum))
    }

    /// Returns self - rhs mod p.
    #[inline]
    fn sub_impl(&self, rhs: &Self) -> Self {
        // Subtract limb by limb, keeping the final borrow mask.
        let mut difference = [0; 6];
        let mut borrow = 0;
        for ((out, a), b) in difference.iter_mut().zip(self.0).zip(rhs.0) {
            (*out, borrow) = sbb(a, b, borrow);
        }

        // On underflow add p back, masked so both paths cost the same.
        let mut carry = 0;
        for (out, modulus) in difference.iter_mut().zip(MODULUS) {
            (*out, carry) = adc(*out, modulus & borrow, carry);
        }
        Self(difference)
    }

    /// Returns self * rhs mod p.
    #[inline]
    fn mul_impl(&self, rhs: &Self) -> Self {
        Self(Self::montgomery_mul(&self.0, &rhs.0))
    }

    /// Returns -self mod p.
    #[inline]
    fn neg_impl(&self) -> Self {
        // Compute p - a limb by limb.
        let mut negated = [0; 6];
        let mut borrow = 0;
        for ((out, modulus), a) in negated.iter_mut().zip(MODULUS).zip(self.0) {
            (*out, borrow) = sbb(modulus, a, borrow);
        }

        // Zero must map to zero, not to p, so mask the result away when the input is zero.
        let keep = mask(!self.is_zero());
        for out in &mut negated {
            *out &= keep;
        }
        Self(negated)
    }
}

impl Add for Fp {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        self.add_impl(&rhs)
    }
}

impl Add<&Self> for Fp {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self {
        self.add_impl(rhs)
    }
}

impl Add<&Fp> for &Fp {
    type Output = Fp;

    #[inline]
    fn add(self, rhs: &Fp) -> Fp {
        self.add_impl(rhs)
    }
}

impl AddAssign for Fp {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add_impl(&rhs);
    }
}

impl AddAssign<&Self> for Fp {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        *self = self.add_impl(rhs);
    }
}

impl Sub for Fp {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        self.sub_impl(&rhs)
    }
}

impl Sub<&Self> for Fp {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &Self) -> Self {
        self.sub_impl(rhs)
    }
}

impl Sub<&Fp> for &Fp {
    type Output = Fp;

    #[inline]
    fn sub(self, rhs: &Fp) -> Fp {
        self.sub_impl(rhs)
    }
}

impl SubAssign for Fp {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub_impl(&rhs);
    }
}

impl SubAssign<&Self> for Fp {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        *self = self.sub_impl(rhs);
    }
}

impl Mul for Fp {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        self.mul_impl(&rhs)
    }
}

impl Mul<&Self> for Fp {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Self) -> Self {
        self.mul_impl(rhs)
    }
}

impl Mul<&Fp> for &Fp {
    type Output = Fp;

    #[inline]
    fn mul(self, rhs: &Fp) -> Fp {
        self.mul_impl(rhs)
    }
}

impl MulAssign for Fp {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul_impl(&rhs);
    }
}

impl MulAssign<&Self> for Fp {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        *self = self.mul_impl(rhs);
    }
}

impl Neg for Fp {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        self.neg_impl()
    }
}

impl Neg for &Fp {
    type Output = Fp;

    #[inline]
    fn neg(self) -> Fp {
        self.neg_impl()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Uniform field elements, drawn by reducing 64 random bytes.
    pub(crate) fn arb_fp() -> impl Strategy<Value = Fp> {
        any::<[u8; 64]>().prop_map(|bytes| Fp::from_bytes_wide_be(&bytes))
    }

    /// Reference product built only from addition, by binary long multiplication.
    fn mul_by_doubling(a: &Fp, b: &Fp) -> Fp {
        let mut result = Fp::ZERO;
        let mut addend = *a;
        // Walk the bits of b from least significant: result += a * 2^i for each set bit i.
        for limb in b.to_canonical() {
            for bit in 0..64 {
                if (limb >> bit) & 1 == 1 {
                    result += addend;
                }
                addend = addend.double();
            }
        }
        result
    }

    #[test]
    fn small_integers_multiply_as_integers() {
        // 6 * 7 = 42 has no reduction, so it checks the Montgomery round trip.
        assert_eq!(Fp::from_u64(6) * Fp::from_u64(7), Fp::from_u64(42));
    }

    #[test]
    fn minus_one_squares_to_one() {
        // p - 1 is the largest element; (-1)^2 = 1 exercises every reduction path.
        let minus_one = -Fp::ONE;
        assert_eq!(minus_one.square(), Fp::ONE);
        assert_eq!(minus_one + Fp::ONE, Fp::ZERO);
    }

    #[test]
    fn negating_zero_gives_zero() {
        // The naive p - 0 = p would be an unreduced representation of zero.
        assert_eq!(-Fp::ZERO, Fp::ZERO);
    }

    #[test]
    fn decoding_rejects_the_modulus_and_accepts_its_predecessor() {
        // Fixture state: the 48-byte big-endian encoding of p.
        let mut bytes = [0_u8; 48];
        limbs_to_be_bytes(&MODULUS, &mut bytes);
        assert_eq!(Fp::from_bytes_be(&bytes), None);

        // Mutation: p - 1 has last byte 0xaa instead of 0xab and is canonical.
        bytes[47] = 0xaa;
        assert_eq!(Fp::from_bytes_be(&bytes), Some(-Fp::ONE));
    }

    #[test]
    fn zero_has_no_inverse() {
        assert_eq!(Fp::ZERO.invert(), None);
    }

    #[test]
    fn minus_one_has_no_square_root() {
        // p = 3 mod 4, so -1 is a non-residue.
        assert_eq!((-Fp::ONE).sqrt(), None);
    }

    #[test]
    fn sign_of_a_pair_is_decided_by_the_half_modulus() {
        // (p - 1) / 2 is not largest; its negation (p + 1) / 2 is.
        let half = Fp(Fp::montgomery_mul(&HALF_MODULUS, &R2));
        assert!(!half.is_lexicographically_largest());
        assert!((-half).is_lexicographically_largest());
        // Zero is its own negation and is never largest.
        assert!(!Fp::ZERO.is_lexicographically_largest());
    }

    #[test]
    fn wide_reduction_matches_integer_arithmetic() {
        // Bytes 0x01 followed by 63 zeros encode 2^504.
        let mut bytes = [0_u8; 64];
        bytes[0] = 1;

        // Reference: 2^504 = (2^63)^8, built with field multiplications.
        let two_63 = Fp::from_u64(1 << 63);
        let expected = (0..7).fold(two_63, |acc, _| acc * two_63);

        assert_eq!(Fp::from_bytes_wide_be(&bytes), expected);
    }

    proptest! {
        #[test]
        fn bytes_round_trip(a in arb_fp()) {
            prop_assert_eq!(Fp::from_bytes_be(&a.to_bytes_be()), Some(a));
        }

        #[test]
        fn montgomery_product_matches_reference(a in arb_fp(), b in arb_fp()) {
            prop_assert_eq!(a * b, mul_by_doubling(&a, &b));
        }

        #[test]
        fn fused_sum_of_products_matches_separate_products(
            a0 in arb_fp(), a1 in arb_fp(), b0 in arb_fp(), b1 in arb_fp()
        ) {
            prop_assert_eq!(Fp::sum_of_products([a0, a1], [b0, b1]), a0 * b0 + a1 * b1);
            // Boundary: every operand p - 1 drives the accumulator to its largest value.
            let top = -Fp::ONE;
            prop_assert_eq!(Fp::sum_of_products([top, top], [top, top]), Fp::from_u64(2));
        }

        #[test]
        fn ring_axioms_hold(a in arb_fp(), b in arb_fp(), c in arb_fp()) {
            // Associativity and commutativity of both operations.
            prop_assert_eq!((a + b) + c, a + (b + c));
            prop_assert_eq!((a * b) * c, a * (b * c));
            prop_assert_eq!(a * b, b * a);
            // Multiplication distributes over addition.
            prop_assert_eq!(a * (b + c), a * b + a * c);
            // Subtraction undoes addition.
            prop_assert_eq!(a + b - b, a);
            prop_assert_eq!(a.square(), a * a);
        }

        #[test]
        fn inverse_is_multiplicative(a in arb_fp()) {
            prop_assume!(!a.is_zero());
            prop_assert_eq!(a * a.invert().unwrap(), Fp::ONE);
        }

        #[test]
        fn squares_have_roots(a in arb_fp()) {
            // Every square has a root, and the root squares back to it.
            let root = a.square().sqrt().unwrap();
            prop_assert_eq!(root.square(), a.square());
        }

        #[test]
        fn exactly_one_of_a_pair_is_largest(a in arb_fp()) {
            prop_assume!(!a.is_zero());
            prop_assert_ne!(a.is_lexicographically_largest(), (-a).is_lexicographically_largest());
        }
    }
}
