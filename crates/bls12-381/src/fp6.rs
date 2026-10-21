//! The cubic extension F_{p^6} = F_{p^2}[v] / (v^3 - xi), with xi = 1 + u.
//!
//! xi is neither a square nor a cube in F_{p^2}, so v^3 = xi defines a field.
//! This is the middle floor of the tower 2 -> 6 -> 12 used by the pairing.

use std::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use crate::{Fp, Fp2};

/// The value xi^{(p-1)/3}, so that v^p = xi^{(p-1)/3} * v.
const FROBENIUS_C1: Fp2 = Fp2::new(
    Fp::ZERO,
    Fp::from_montgomery([
        0xcd03_c9e4_8671_f071,
        0x5dab_2246_1fcd_a5d2,
        0x5870_42af_d385_1b95,
        0x8eb6_0ebe_01ba_cb9e,
        0x03f9_7d6e_83d0_50d2,
        0x18f0_2065_5463_8741,
    ]),
);

/// The value xi^{2(p-1)/3}, so that (v^2)^p = xi^{2(p-1)/3} * v^2.
const FROBENIUS_C2: Fp2 = Fp2::new(
    Fp::from_montgomery([
        0x890d_c9e4_8675_45c3,
        0x2af3_2253_3285_a5d5,
        0x5088_0866_309b_7e2c,
        0xa20d_1b8c_7e88_1024,
        0x14e4_f04f_e2db_9068,
        0x14e5_6d3f_1564_853a,
    ]),
    Fp::ZERO,
);

/// An element c0 + c1 * v + c2 * v^2 of F_{p^6}, where v^3 = 1 + u.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Fp6 {
    /// The coefficient of 1.
    pub c0: Fp2,
    /// The coefficient of v.
    pub c1: Fp2,
    /// The coefficient of v^2.
    pub c2: Fp2,
}

impl Fp6 {
    /// The additive identity.
    pub const ZERO: Self = Self::new(Fp2::ZERO, Fp2::ZERO, Fp2::ZERO);

    /// The multiplicative identity.
    pub const ONE: Self = Self::new(Fp2::ONE, Fp2::ZERO, Fp2::ZERO);

    /// Builds c0 + c1 * v + c2 * v^2.
    #[must_use]
    pub const fn new(c0: Fp2, c1: Fp2, c2: Fp2) -> Self {
        Self { c0, c1, c2 }
    }

    /// Whether the element is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() & self.c1.is_zero() & self.c2.is_zero()
    }

    /// Returns 2 * self.
    #[must_use]
    pub fn double(&self) -> Self {
        Self::new(self.c0.double(), self.c1.double(), self.c2.double())
    }

    /// Multiplies by v, the non-residue that defines the quadratic floor above this field.
    #[must_use]
    pub fn mul_by_nonresidue(&self) -> Self {
        // Shift the coefficients up one power of v; the overflow v^3 wraps to xi.
        //
        //     (c0 + c1 v + c2 v^2) v = c2 xi + c0 v + c1 v^2
        Self::new(self.c2.mul_by_nonresidue(), self.c0, self.c1)
    }

    /// Multiplies by the sparse element b1 * v.
    #[must_use]
    pub fn mul_by_1(&self, b1: &Fp2) -> Self {
        // Each coefficient moves up one power of v, so three products suffice.
        Self::new(
            (self.c2 * b1).mul_by_nonresidue(),
            self.c0 * b1,
            self.c1 * b1,
        )
    }

    /// Multiplies by the sparse element b0 + b1 * v.
    #[must_use]
    pub fn mul_by_01(&self, b0: &Fp2, b1: &Fp2) -> Self {
        // Karatsuba on the two nonzero coefficients: five products instead of six.
        let a0_b0 = self.c0 * b0;
        let a1_b1 = self.c1 * b1;

        // c0 = a0 b0 + xi a2 b1
        let c0 = (self.c2 * b1).mul_by_nonresidue() + a0_b0;
        // c1 = a0 b1 + a1 b0
        let c1 = (*b0 + b1) * (self.c0 + self.c1) - a0_b0 - a1_b1;
        // c2 = a2 b0 + a1 b1
        let c2 = self.c2 * b0 + a1_b1;
        Self::new(c0, c1, c2)
    }

    /// Returns self^2.
    #[must_use]
    pub fn square(&self) -> Self {
        // Chung and Hasan, "Asymmetric squaring formulae", algorithm SQR2.
        //
        //     s0 = a0^2,  s1 = 2 a0 a1,  s2 = (a0 - a1 + a2)^2,  s3 = 2 a1 a2,  s4 = a2^2
        //     c0 = s0 + xi s3
        //     c1 = s1 + xi s4
        //     c2 = s1 + s2 + s3 - s0 - s4
        let s0 = self.c0.square();
        let s1 = (self.c0 * self.c1).double();
        let s2 = (self.c0 - self.c1 + self.c2).square();
        let s3 = (self.c1 * self.c2).double();
        let s4 = self.c2.square();
        Self::new(
            s3.mul_by_nonresidue() + s0,
            s4.mul_by_nonresidue() + s1,
            s1 + s2 + s3 - s0 - s4,
        )
    }

    /// Raises the element to the power p.
    #[must_use]
    pub fn frobenius_map(&self) -> Self {
        // The map is additive, so apply it per coefficient and to the powers of v.
        //
        //     (c0 + c1 v + c2 v^2)^p = c0^p + c1^p v^p + c2^p v^{2p}
        //     v^p = xi^{(p-1)/3} v,   v^{2p} = xi^{2(p-1)/3} v^2
        Self::new(
            self.c0.conjugate(),
            self.c1.conjugate() * FROBENIUS_C1,
            self.c2.conjugate() * FROBENIUS_C2,
        )
    }

    /// Computes the multiplicative inverse.
    ///
    /// # Returns
    ///
    /// The inverse, or nothing for zero.
    #[must_use]
    pub fn invert(&self) -> Option<Self> {
        // Multiply by the adjugate to reach F_{p^2}, invert there, and scale back.
        //
        //     t0 = a0^2 - xi a1 a2
        //     t1 = xi a2^2 - a0 a1
        //     t2 = a1^2 - a0 a2
        //     norm = a0 t0 + xi (a2 t1 + a1 t2)
        let t0 = self.c0.square() - (self.c1 * self.c2).mul_by_nonresidue();
        let t1 = self.c2.square().mul_by_nonresidue() - self.c0 * self.c1;
        let t2 = self.c1.square() - self.c0 * self.c2;
        let norm = self.c0 * t0 + (self.c2 * t1 + self.c1 * t2).mul_by_nonresidue();

        let inverse_norm = norm.invert()?;
        Some(Self::new(
            t0 * inverse_norm,
            t1 * inverse_norm,
            t2 * inverse_norm,
        ))
    }

    /// Returns self + rhs.
    #[inline]
    fn add_impl(&self, rhs: &Self) -> Self {
        Self::new(self.c0 + rhs.c0, self.c1 + rhs.c1, self.c2 + rhs.c2)
    }

    /// Returns self - rhs.
    #[inline]
    fn sub_impl(&self, rhs: &Self) -> Self {
        Self::new(self.c0 - rhs.c0, self.c1 - rhs.c1, self.c2 - rhs.c2)
    }

    /// Returns self * rhs.
    #[inline]
    fn mul_impl(&self, rhs: &Self) -> Self {
        // Karatsuba over three coefficients: six products instead of nine.
        //
        //     c0 = a0 b0 + xi (a1 b2 + a2 b1)
        //     c1 = a0 b1 + a1 b0 + xi a2 b2
        //     c2 = a0 b2 + a2 b0 + a1 b1
        let (a0, a1, a2) = (self.c0, self.c1, self.c2);
        let (b0, b1, b2) = (rhs.c0, rhs.c1, rhs.c2);
        let t0 = a0 * b0;
        let t1 = a1 * b1;
        let t2 = a2 * b2;

        // (a1 + a2)(b1 + b2) - t1 - t2 = a1 b2 + a2 b1
        let c0 = ((a1 + a2) * (b1 + b2) - t1 - t2).mul_by_nonresidue() + t0;
        // (a0 + a1)(b0 + b1) - t0 - t1 = a0 b1 + a1 b0
        let c1 = (a0 + a1) * (b0 + b1) - t0 - t1 + t2.mul_by_nonresidue();
        // (a0 + a2)(b0 + b2) - t0 - t2 = a0 b2 + a2 b0
        let c2 = (a0 + a2) * (b0 + b2) - t0 - t2 + t1;
        Self::new(c0, c1, c2)
    }

    /// Returns -self.
    #[inline]
    fn neg_impl(&self) -> Self {
        Self::new(-self.c0, -self.c1, -self.c2)
    }
}

impl fmt::Debug for Fp6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({:?}) + ({:?}) * v + ({:?}) * v^2",
            self.c0, self.c1, self.c2
        )
    }
}

impl Add for Fp6 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        self.add_impl(&rhs)
    }
}

impl Add<&Self> for Fp6 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self {
        self.add_impl(rhs)
    }
}

impl Add<&Fp6> for &Fp6 {
    type Output = Fp6;

    #[inline]
    fn add(self, rhs: &Fp6) -> Fp6 {
        self.add_impl(rhs)
    }
}

impl AddAssign for Fp6 {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add_impl(&rhs);
    }
}

impl AddAssign<&Self> for Fp6 {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        *self = self.add_impl(rhs);
    }
}

impl Sub for Fp6 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        self.sub_impl(&rhs)
    }
}

impl Sub<&Self> for Fp6 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &Self) -> Self {
        self.sub_impl(rhs)
    }
}

impl Sub<&Fp6> for &Fp6 {
    type Output = Fp6;

    #[inline]
    fn sub(self, rhs: &Fp6) -> Fp6 {
        self.sub_impl(rhs)
    }
}

impl SubAssign for Fp6 {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub_impl(&rhs);
    }
}

impl SubAssign<&Self> for Fp6 {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        *self = self.sub_impl(rhs);
    }
}

impl Mul for Fp6 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        self.mul_impl(&rhs)
    }
}

impl Mul<&Self> for Fp6 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Self) -> Self {
        self.mul_impl(rhs)
    }
}

impl Mul<&Fp6> for &Fp6 {
    type Output = Fp6;

    #[inline]
    fn mul(self, rhs: &Fp6) -> Fp6 {
        self.mul_impl(rhs)
    }
}

impl MulAssign for Fp6 {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul_impl(&rhs);
    }
}

impl MulAssign<&Self> for Fp6 {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        *self = self.mul_impl(rhs);
    }
}

impl Neg for Fp6 {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        self.neg_impl()
    }
}

impl Neg for &Fp6 {
    type Output = Fp6;

    #[inline]
    fn neg(self) -> Fp6 {
        self.neg_impl()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::fp2::tests::arb_fp2;

    /// Uniform elements of F_{p^6}.
    pub(crate) fn arb_fp6() -> impl Strategy<Value = Fp6> {
        (arb_fp2(), arb_fp2(), arb_fp2()).prop_map(|(c0, c1, c2)| Fp6::new(c0, c1, c2))
    }

    #[test]
    fn v_cubed_is_xi() {
        // The defining relation of the cubic floor.
        let v = Fp6::new(Fp2::ZERO, Fp2::ONE, Fp2::ZERO);
        let xi = Fp6::new(Fp2::new(Fp::ONE, Fp::ONE), Fp2::ZERO, Fp2::ZERO);
        assert_eq!(v * v * v, xi);
    }

    proptest! {
        #[test]
        fn field_axioms_hold(a in arb_fp6(), b in arb_fp6(), c in arb_fp6()) {
            prop_assert_eq!((a * b) * c, a * (b * c));
            prop_assert_eq!(a * b, b * a);
            prop_assert_eq!(a * (b + c), a * b + a * c);
            prop_assert_eq!(a.square(), a * a);
        }

        #[test]
        fn inverse_is_multiplicative(a in arb_fp6()) {
            prop_assume!(!a.is_zero());
            prop_assert_eq!(a * a.invert().unwrap(), Fp6::ONE);
        }

        #[test]
        fn sparse_products_match_dense(a in arb_fp6(), b0 in arb_fp2(), b1 in arb_fp2()) {
            prop_assert_eq!(a.mul_by_1(&b1), a * Fp6::new(Fp2::ZERO, b1, Fp2::ZERO));
            prop_assert_eq!(a.mul_by_01(&b0, &b1), a * Fp6::new(b0, b1, Fp2::ZERO));
        }

        #[test]
        fn nonresidue_product_matches_generic(a in arb_fp6()) {
            let v = Fp6::new(Fp2::ZERO, Fp2::ONE, Fp2::ZERO);
            prop_assert_eq!(a.mul_by_nonresidue(), a * v);
        }

        #[test]
        fn frobenius_is_a_ring_morphism(a in arb_fp6(), b in arb_fp6()) {
            // (ab)^p = a^p b^p and (a + b)^p = a^p + b^p.
            prop_assert_eq!((a * b).frobenius_map(), a.frobenius_map() * b.frobenius_map());
            prop_assert_eq!((a + b).frobenius_map(), a.frobenius_map() + b.frobenius_map());
        }

        #[test]
        fn frobenius_has_order_six(a in arb_fp6()) {
            // x^{p^6} = x on F_{p^6}, while x^{p^3} moves a generic element.
            let mut image = a;
            for _ in 0..6 {
                image = image.frobenius_map();
            }
            prop_assert_eq!(image, a);
        }
    }
}
