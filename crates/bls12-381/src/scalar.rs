//! The scalar field F_r of BLS12-381, where r is the 255-bit prime order of G1, G2, and GT.
//!
//! # Overview
//!
//! Elements live in Montgomery form with R = 2^256, exactly as base-field elements do with 2^384.
//! The field has 2-adicity 32: r - 1 = 2^32 * t with t odd.
//! That gives roots of unity of every power-of-two order up to 2^32, which FFTs over this field need.
//!
//! Arithmetic runs in time independent of its operands, so secret keys can be scalars.

use std::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use crate::arithmetic::{adc, limbs_from_be_bytes, limbs_to_be_bytes, mac, mask, sbb};

/// The group order r, as little-endian 64-bit limbs.
///
/// r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001.
const MODULUS: [u64; 4] = [
    0xffff_ffff_0000_0001,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
];

/// The constant -r^{-1} mod 2^64, used by Montgomery reduction.
const INV: u64 = 0xffff_fffe_ffff_ffff;

/// The value R = 2^256 mod r, which is the Montgomery form of one.
const R: [u64; 4] = [
    0x0000_0001_ffff_fffe,
    0x5884_b7fa_0003_4802,
    0x998c_4fef_ecbc_4ff5,
    0x1824_b159_acc5_056f,
];

/// The value R^2 mod r, which maps a reduced integer to its Montgomery form.
const R2: [u64; 4] = [
    0xc999_e990_f3f2_9c6d,
    0x2b6c_edcb_8792_5c23,
    0x05d3_1496_7254_398f,
    0x0748_d9d9_9f59_ff11,
];

/// The exponent r - 2, which inverts by Fermat's little theorem.
const R_MINUS_2: [u64; 4] = [
    0xffff_fffe_ffff_ffff,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
];

/// Number of bytes in the canonical big-endian encoding of a scalar.
pub const SCALAR_BYTES: usize = 32;

/// An element of the scalar field F_r.
///
/// The limbs hold the Montgomery form, always fully reduced below r.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Scalar(pub(crate) [u64; 4]);

impl Scalar {
    /// The additive identity.
    pub const ZERO: Self = Self([0; 4]);

    /// The multiplicative identity.
    pub const ONE: Self = Self(R);

    /// The exponent s in r - 1 = 2^s * t with t odd.
    pub const TWO_ADICITY: u32 = 32;

    /// The generator 7 of the multiplicative group of F_r.
    ///
    /// It is the smallest integer that is a non-residue for every prime factor of r - 1.
    pub const MULTIPLICATIVE_GENERATOR: Self = Self([
        0x0000_000e_ffff_fff1,
        0x17e3_63d3_0018_9c0f,
        0xff9c_5787_6f84_57b0,
        0x3513_3220_8fc5_a8c4,
    ]);

    /// A primitive root of unity of order 2^32.
    ///
    /// It is the generator raised to the odd part t of r - 1, so its order is exactly 2^32.
    pub const ROOT_OF_UNITY: Self = Self([
        0xb9b5_8d8c_5f0e_466a,
        0x5b1b_4c80_1819_d7ec,
        0x0af5_3ae3_52a3_1e64,
        0x5bf3_adda_19e9_b27b,
    ]);

    /// Embeds a small integer into the field.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        // value < 2^64 < r is reduced.
        // One product with R^2 gives its Montgomery form.
        Self(Self::montgomery_mul(&[value, 0, 0, 0], &R2))
    }

    /// Decodes a canonical big-endian encoding.
    ///
    /// # Returns
    ///
    /// The scalar, or nothing when the integer is not below r.
    #[must_use]
    pub fn from_bytes_be(bytes: &[u8; SCALAR_BYTES]) -> Option<Self> {
        let limbs: [u64; 4] = limbs_from_be_bytes(bytes);

        // A borrow out of limbs - r means limbs < r, the only canonical case.
        let mut borrow = 0;
        for (limb, modulus) in limbs.iter().zip(MODULUS) {
            (_, borrow) = sbb(*limb, modulus, borrow);
        }
        if borrow == 0 {
            return None;
        }
        Some(Self(Self::montgomery_mul(&limbs, &R2)))
    }

    /// Reduces any 32-byte big-endian integer modulo r.
    ///
    /// This is the reduction of the consensus specs' hash-to-scalar step, as in hash_to_bls_field.
    #[must_use]
    pub fn from_bytes_be_reduced(bytes: &[u8; SCALAR_BYTES]) -> Self {
        let mut limbs: [u64; 4] = limbs_from_be_bytes(bytes);

        // Bound: 2^256 < 3r, so at most two subtractions of r bring the value below r.
        limbs = Self::subtract_modulus_if_needed(limbs);
        limbs = Self::subtract_modulus_if_needed(limbs);
        Self(Self::montgomery_mul(&limbs, &R2))
    }

    /// Encodes the scalar as 32 canonical big-endian bytes.
    #[must_use]
    pub fn to_bytes_be(&self) -> [u8; SCALAR_BYTES] {
        let mut out = [0; SCALAR_BYTES];
        limbs_to_be_bytes(&self.to_canonical(), &mut out);
        out
    }

    /// The canonical integer in [0, r), as little-endian 64-bit limbs.
    #[must_use]
    pub fn to_canonical(&self) -> [u64; 4] {
        // A Montgomery product with plain 1 strips the factor R.
        Self::montgomery_mul(&self.0, &[1, 0, 0, 0])
    }

    /// Whether the scalar is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
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

    /// Raises the scalar to a power given as little-endian limbs.
    ///
    /// The running time depends on the exponent, never on the base.
    #[must_use]
    pub fn pow_vartime(&self, exponent: &[u64]) -> Self {
        let mut result = Self::ONE;
        // Left-to-right square-and-multiply.
        for limb in exponent.iter().rev() {
            for bit in (0..64).rev() {
                result = result.square();
                if (limb >> bit) & 1 == 1 {
                    result *= self;
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
        // Fermat: a^{r-2} = a^{-1}, with a public exponent.
        let inverse = self.pow_vartime(&R_MINUS_2);
        (!self.is_zero()).then_some(inverse)
    }

    /// Inverts every scalar of a slice in place with a single field inversion.
    ///
    /// Zero entries stay zero.
    ///
    /// # Algorithm
    ///
    /// Montgomery's trick: one inversion of the running product, then two products per element.
    ///
    /// ```text
    ///     prefix_i = a_0 a_1 ... a_i
    ///     a_i^{-1} = prefix_{i-1} * prefix_i^{-1}
    ///     prefix_{i-1}^{-1} = prefix_i^{-1} * a_i
    /// ```
    pub fn batch_invert(values: &mut [Self]) {
        // Phase 1: running products of the nonzero entries.
        let mut prefixes = Vec::with_capacity(values.len());
        let mut product = Self::ONE;
        for value in values.iter() {
            prefixes.push(product);
            if !value.is_zero() {
                product *= value;
            }
        }

        // Phase 2: invert the total product once.
        // Every factor is nonzero, so the product is too.
        let Some(mut inverse) = product.invert() else {
            return;
        };

        // Phase 3: walk back, peeling one factor off the inverse at each step.
        for (value, prefix) in values.iter_mut().zip(prefixes).rev() {
            if value.is_zero() {
                continue;
            }
            // inverse = (a_0 ... a_i)^{-1}, prefix = a_0 ... a_{i-1}
            let next_inverse = inverse * *value;
            *value = inverse * prefix;
            inverse = next_inverse;
        }
    }

    /// A primitive root of unity of order 2^k.
    ///
    /// # Returns
    ///
    /// The root, or nothing when k exceeds the 2-adicity 32.
    #[must_use]
    pub fn root_of_unity(log_order: u32) -> Option<Self> {
        if log_order > Self::TWO_ADICITY {
            return None;
        }
        // Squaring halves the order: (omega^{2^j}) has order 2^{32 - j}.
        let mut root = Self::ROOT_OF_UNITY;
        for _ in log_order..Self::TWO_ADICITY {
            root = root.square();
        }
        Some(root)
    }

    /// Montgomery multiplication: returns a * b * R^{-1} mod r, fully reduced.
    ///
    /// The no-carry CIOS variant applies because the top limb of r is below 2^63 - 1.
    /// The base field documents the algorithm in full.
    #[allow(
        clippy::needless_range_loop,
        reason = "the limb index drives two arrays at once"
    )]
    fn montgomery_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let mut t = [0_u64; 4];
        for i in 0..4 {
            // Add the low limb of a * b_i, then choose m to clear it.
            let (t0, mut carry_ab) = mac(t[0], a[0], b[i], 0);
            let m = t0.wrapping_mul(INV);
            let (_, mut carry_mp) = mac(t0, m, MODULUS[0], 0);

            // Accumulate the other limbs while shifting down by one limb.
            for j in 1..4 {
                let (tj, carry) = mac(t[j], a[j], b[i], carry_ab);
                carry_ab = carry;
                let (shifted, carry) = mac(tj, m, MODULUS[j], carry_mp);
                carry_mp = carry;
                t[j - 1] = shifted;
            }
            t[3] = carry_ab.wrapping_add(carry_mp);
        }
        Self::subtract_modulus_if_needed(t)
    }

    /// Maps a value in [0, 2r) to [0, r) without branching.
    fn subtract_modulus_if_needed(value: [u64; 4]) -> [u64; 4] {
        let mut reduced = [0; 4];
        let mut borrow = 0;
        for ((out, limb), modulus) in reduced.iter_mut().zip(value).zip(MODULUS) {
            (*out, borrow) = sbb(limb, modulus, borrow);
        }
        // Keep the original when the subtraction borrowed.
        let mut out = [0; 4];
        for ((out, reduced), original) in out.iter_mut().zip(reduced).zip(value) {
            *out = (reduced & !borrow) | (original & borrow);
        }
        out
    }

    /// Returns self + rhs mod r.
    #[inline]
    fn add_impl(&self, rhs: &Self) -> Self {
        // r < 2^255, so the sum of two reduced values fits in four limbs.
        let mut sum = [0; 4];
        let mut carry = 0;
        for ((out, a), b) in sum.iter_mut().zip(self.0).zip(rhs.0) {
            (*out, carry) = adc(a, b, carry);
        }
        Self(Self::subtract_modulus_if_needed(sum))
    }

    /// Returns self - rhs mod r.
    #[inline]
    fn sub_impl(&self, rhs: &Self) -> Self {
        let mut difference = [0; 4];
        let mut borrow = 0;
        for ((out, a), b) in difference.iter_mut().zip(self.0).zip(rhs.0) {
            (*out, borrow) = sbb(a, b, borrow);
        }
        // Add r back on underflow, masked to keep constant time.
        let mut carry = 0;
        for (out, modulus) in difference.iter_mut().zip(MODULUS) {
            (*out, carry) = adc(*out, modulus & borrow, carry);
        }
        Self(difference)
    }

    /// Returns self * rhs mod r.
    #[inline]
    fn mul_impl(&self, rhs: &Self) -> Self {
        Self(Self::montgomery_mul(&self.0, &rhs.0))
    }

    /// Returns -self mod r.
    #[inline]
    fn neg_impl(&self) -> Self {
        let mut negated = [0; 4];
        let mut borrow = 0;
        for ((out, modulus), a) in negated.iter_mut().zip(MODULUS).zip(self.0) {
            (*out, borrow) = sbb(modulus, a, borrow);
        }
        // Zero maps to zero, not to r.
        let keep = mask(!self.is_zero());
        for out in &mut negated {
            *out &= keep;
        }
        Self(negated)
    }
}

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Scalar {
    /// Renders the canonical integer as 0x-prefixed big-endian hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Big-endian bytes of the canonical integer.
        f.write_str("0x")?;
        for byte in self.to_bytes_be() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Add for Scalar {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        self.add_impl(&rhs)
    }
}

impl Add<&Self> for Scalar {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self {
        self.add_impl(rhs)
    }
}

impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    #[inline]
    fn add(self, rhs: &Scalar) -> Scalar {
        self.add_impl(rhs)
    }
}

impl AddAssign for Scalar {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add_impl(&rhs);
    }
}

impl AddAssign<&Self> for Scalar {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        *self = self.add_impl(rhs);
    }
}

impl Sub for Scalar {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        self.sub_impl(&rhs)
    }
}

impl Sub<&Self> for Scalar {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &Self) -> Self {
        self.sub_impl(rhs)
    }
}

impl Sub<&Scalar> for &Scalar {
    type Output = Scalar;

    #[inline]
    fn sub(self, rhs: &Scalar) -> Scalar {
        self.sub_impl(rhs)
    }
}

impl SubAssign for Scalar {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub_impl(&rhs);
    }
}

impl SubAssign<&Self> for Scalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        *self = self.sub_impl(rhs);
    }
}

impl Mul for Scalar {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        self.mul_impl(&rhs)
    }
}

impl Mul<&Self> for Scalar {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Self) -> Self {
        self.mul_impl(rhs)
    }
}

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    #[inline]
    fn mul(self, rhs: &Scalar) -> Scalar {
        self.mul_impl(rhs)
    }
}

impl MulAssign for Scalar {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul_impl(&rhs);
    }
}

impl MulAssign<&Self> for Scalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        *self = self.mul_impl(rhs);
    }
}

impl Neg for Scalar {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        self.neg_impl()
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    #[inline]
    fn neg(self) -> Scalar {
        self.neg_impl()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Uniform-enough scalars, drawn by reducing 32 random bytes.
    pub(crate) fn arb_scalar() -> impl Strategy<Value = Scalar> {
        any::<[u8; 32]>().prop_map(|bytes| Scalar::from_bytes_be_reduced(&bytes))
    }

    /// Reference product built only from addition, by binary long multiplication.
    fn mul_by_doubling(a: &Scalar, b: &Scalar) -> Scalar {
        // Add a * 2^i for every set bit i of b.
        let mut result = Scalar::ZERO;
        let mut addend = *a;
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
    fn decoding_rejects_the_modulus() {
        // Fixture state: r itself, which is congruent to zero but not canonical.
        let mut bytes = [0_u8; 32];
        limbs_to_be_bytes(&MODULUS, &mut bytes);
        assert_eq!(Scalar::from_bytes_be(&bytes), None);

        // The reducing decoder maps the same bytes to zero instead.
        assert_eq!(Scalar::from_bytes_be_reduced(&bytes), Scalar::ZERO);
    }

    #[test]
    fn reduction_of_all_ones_matches_arithmetic() {
        // 2^256 - 1 = 2 * r + k for a k below r.
        // Check against field arithmetic.
        //
        //     2^256 - 1 = (2^128)^2 - 1
        let two_64 = Scalar::from_u64(u64::MAX) + Scalar::ONE;
        let two_128 = two_64 * two_64;
        let expected = two_128 * two_128 - Scalar::ONE;
        assert_eq!(Scalar::from_bytes_be_reduced(&[0xff; 32]), expected);
    }

    #[test]
    fn root_of_unity_has_exact_order() {
        // omega^{2^31} = -1 and omega^{2^32} = 1 together pin the order at exactly 2^32.
        let mut power = Scalar::ROOT_OF_UNITY;
        for _ in 0..31 {
            power = power.square();
        }
        assert_eq!(power, -Scalar::ONE);
        assert_eq!(power.square(), Scalar::ONE);
    }

    #[test]
    fn small_roots_of_unity_are_known() {
        // Order 1 is the root 1 and order 2 is the root -1.
        assert_eq!(Scalar::root_of_unity(0), Some(Scalar::ONE));
        assert_eq!(Scalar::root_of_unity(1), Some(-Scalar::ONE));
        // Order 2^12 = 4096, the blob size of EIP-4844, has its 4096th power equal to one.
        let root = Scalar::root_of_unity(12).unwrap();
        assert_eq!(root.pow_vartime(&[4096]), Scalar::ONE);
        assert_ne!(root.pow_vartime(&[2048]), Scalar::ONE);
        // Order 2^33 does not exist.
        assert_eq!(Scalar::root_of_unity(33), None);
    }

    #[test]
    fn generator_is_a_non_residue() {
        // Euler's criterion: 7^{(r-1)/2} = -1, so 7 generates the 2-Sylow part.
        let half_order = [
            0x7fff_ffff_8000_0000,
            0xa9de_d201_7fff_2dff,
            0x199c_ec04_04d0_ec02,
            0x39f6_d3a9_94ce_bea4,
        ];
        assert_eq!(
            Scalar::MULTIPLICATIVE_GENERATOR.pow_vartime(&half_order),
            -Scalar::ONE
        );
        assert_eq!(Scalar::MULTIPLICATIVE_GENERATOR, Scalar::from_u64(7));
    }

    #[test]
    fn batch_inversion_skips_zeros() {
        // Fixture state: [2, 0, 3] inverts to [1/2, 0, 1/3].
        let mut values = [Scalar::from_u64(2), Scalar::ZERO, Scalar::from_u64(3)];
        Scalar::batch_invert(&mut values);
        assert_eq!(
            values,
            [
                Scalar::from_u64(2).invert().unwrap(),
                Scalar::ZERO,
                Scalar::from_u64(3).invert().unwrap(),
            ]
        );
    }

    proptest! {
        #[test]
        fn bytes_round_trip(a in arb_scalar()) {
            prop_assert_eq!(Scalar::from_bytes_be(&a.to_bytes_be()), Some(a));
        }

        #[test]
        fn montgomery_product_matches_reference(a in arb_scalar(), b in arb_scalar()) {
            prop_assert_eq!(a * b, mul_by_doubling(&a, &b));
        }

        #[test]
        fn field_axioms_hold(a in arb_scalar(), b in arb_scalar(), c in arb_scalar()) {
            prop_assert_eq!((a + b) + c, a + (b + c));
            // Associativity and commutativity of the product, then distributivity.
            prop_assert_eq!((a * b) * c, a * (b * c));
            prop_assert_eq!(a * b, b * a);
            prop_assert_eq!(a * (b + c), a * b + a * c);
            // Subtraction and negation undo addition.
            prop_assert_eq!(a - b + b, a);
            prop_assert_eq!(a + (-a), Scalar::ZERO);
            // The dedicated squaring agrees with the generic product.
            prop_assert_eq!(a.square(), a * a);
        }

        #[test]
        fn inverse_is_multiplicative(a in arb_scalar()) {
            prop_assume!(!a.is_zero());
            prop_assert_eq!(a * a.invert().unwrap(), Scalar::ONE);
        }

        #[test]
        fn batch_inversion_matches_single(values in proptest::collection::vec(arb_scalar(), 0..20)) {
            // Zeros map to zero, everything else to its own inverse.
            let mut batch = values.clone();
            Scalar::batch_invert(&mut batch);
            for (inverse, value) in batch.iter().zip(&values) {
                prop_assert_eq!(*inverse, value.invert().unwrap_or(Scalar::ZERO));
            }
        }

        #[test]
        fn pow_adds_exponents(a in arb_scalar(), e1 in any::<u64>(), e2 in any::<u32>()) {
            // a^{e1 + e2} = a^{e1} a^{e2}, with the sum computed in 128 bits.
            let sum = u128::from(e1) + u128::from(e2);
            let limbs = [u64::try_from(sum & u128::from(u64::MAX)).unwrap(), u64::try_from(sum >> 64).unwrap()];
            prop_assert_eq!(
                a.pow_vartime(&limbs),
                a.pow_vartime(&[e1]) * a.pow_vartime(&[u64::from(e2)])
            );
        }
    }
}
