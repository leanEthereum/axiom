//! The quadratic extension F_{p^12} = F_{p^6}\[w\] / (w^2 - v), the target field of the pairing.
//!
//! Over F_{p^2} the element w satisfies w^6 = xi, so the six powers below form a basis:
//!
//! ```text
//!     c0 = (1, v, v^2)       = (w^0, w^2, w^4)
//!     c1 = (w, v w, v^2 w)   = (w^1, w^3, w^5)
//! ```

use std::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use crate::{BLS_X, Fp, Fp2, Fp6};

/// The value xi^{(p-1)/6}, so that w^p = xi^{(p-1)/6} * w.
const FROBENIUS_C1: Fp2 = Fp2::new(
    Fp::from_montgomery([
        0x0708_9552_b319_d465,
        0xc669_5f92_b50a_8313,
        0x97e8_3ccc_d117_228f,
        0xa35b_aeca_b2dc_29ee,
        0x1ce3_93ea_5daa_ce4d,
        0x08f2_220f_b0fb_66eb,
    ]),
    Fp::from_montgomery([
        0xb2f6_6aad_4ce5_d646,
        0x5842_a06b_fc49_7cec,
        0xcf48_95d4_2599_d394,
        0xc11b_9cba_40a8_e8d0,
        0x2e38_13cb_e5a0_de89,
        0x110e_efda_8884_7faf,
    ]),
);

/// An element c0 + c1 * w of F_{p^12}, where w^2 = v.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Fp12 {
    /// The coefficient of 1.
    pub c0: Fp6,
    /// The coefficient of w.
    pub c1: Fp6,
}

impl Fp12 {
    /// The additive identity.
    pub const ZERO: Self = Self::new(Fp6::ZERO, Fp6::ZERO);

    /// The multiplicative identity.
    pub const ONE: Self = Self::new(Fp6::ONE, Fp6::ZERO);

    /// Builds c0 + c1 * w.
    #[must_use]
    pub const fn new(c0: Fp6, c1: Fp6) -> Self {
        Self { c0, c1 }
    }

    /// Whether the element is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() & self.c1.is_zero()
    }

    /// Returns the conjugate c0 - c1 * w, which is the power x^{p^6}.
    ///
    /// On the cyclotomic subgroup, where x^{p^6 + 1} = 1, conjugation is inversion.
    #[must_use]
    pub fn conjugate(&self) -> Self {
        Self::new(self.c0, -self.c1)
    }

    /// Returns self^2.
    #[must_use]
    pub fn square(&self) -> Self {
        // Complex squaring over w^2 = v, two F_{p^6} products.
        //
        //     (a + b w)^2 = (a^2 + v b^2) + 2ab w
        //     (a + b)(a + v b) = a^2 + v b^2 + (1 + v) ab
        let ab = self.c0 * self.c1;
        let c0 = (self.c0 + self.c1) * (self.c0 + self.c1.mul_by_nonresidue())
            - ab
            - ab.mul_by_nonresidue();
        Self::new(c0, ab.double())
    }

    /// Multiplies by the sparse element b0 + b1 * v + b4 * v * w.
    ///
    /// Miller-loop lines have exactly this shape, in the basis positions 0, 1, and 4.
    #[must_use]
    pub fn mul_by_014(&self, b0: &Fp2, b1: &Fp2, b4: &Fp2) -> Self {
        // Karatsuba over w with sparse halves.
        //
        //     rhs = B0 + B1 w,   B0 = b0 + b1 v,   B1 = b4 v
        let aa = self.c0.mul_by_01(b0, b1);
        let bb = self.c1.mul_by_1(b4);

        // (a0 + a1)(B0 + B1) = a0 B0 + a1 B1 + (a0 B1 + a1 B0)
        let b1_plus_b4 = *b1 + b4;
        let c1 = (self.c1 + self.c0).mul_by_01(b0, &b1_plus_b4) - aa - bb;
        // The w^2 = v wrap-around folds a1 B1 into the constant half.
        let c0 = bb.mul_by_nonresidue() + aa;
        Self::new(c0, c1)
    }

    /// Raises the element to the power p.
    #[must_use]
    pub fn frobenius_map(&self) -> Self {
        // (c0 + c1 w)^p = c0^p + c1^p w^p, and w^p = xi^{(p-1)/6} w.
        let c0 = self.c0.frobenius_map();
        let c1 = self.c1.frobenius_map();
        let c1 = Fp6::new(
            c1.c0 * FROBENIUS_C1,
            c1.c1 * FROBENIUS_C1,
            c1.c2 * FROBENIUS_C1,
        );
        Self::new(c0, c1)
    }

    /// Computes the multiplicative inverse.
    ///
    /// # Returns
    ///
    /// The inverse, or nothing for zero.
    #[must_use]
    pub fn invert(&self) -> Option<Self> {
        // Multiply by the conjugate to land in F_{p^6}.
        //
        //     1 / (a + b w) = (a - b w) / (a^2 - v b^2)
        let norm = self.c0.square() - self.c1.square().mul_by_nonresidue();
        let inverse_norm = norm.invert()?;
        Some(Self::new(self.c0 * inverse_norm, -(self.c1 * inverse_norm)))
    }

    /// Raises an element of the cyclotomic subgroup to the curve parameter x = -0xd201000000010000.
    ///
    /// The result is wrong for elements outside that subgroup, as for the cyclotomic square.
    #[must_use]
    pub(crate) fn cyclotomic_exp_by_x(&self) -> Self {
        // Square-and-multiply over |x|, whose top bit 63 seeds the accumulator.
        let mut acc = *self;
        for bit in (0..63).rev() {
            acc = acc.cyclotomic_square();
            if (BLS_X >> bit) & 1 == 1 {
                acc *= self;
            }
        }
        // x is negative, and inversion in the cyclotomic subgroup is conjugation.
        acc.conjugate()
    }

    /// Squares an element of the cyclotomic subgroup, the elements with x^{p^4 - p^2 + 1} = 1.
    ///
    /// The result is wrong for elements outside that subgroup.
    /// Every output of the easy part of the final exponentiation lies inside it.
    ///
    /// # Algorithm
    ///
    /// See Granger and Scott, eprint 2009/565, section 3.2.
    /// View the element as three F_{p^4} coordinates over F_{p^2}, with s = w^3 and s^2 = xi:
    ///
    /// ```text
    ///     A = z0 + z1 s,   B = z2 + z3 s,   C = z4 + z5 s
    ///     x = A + B w + C w^2
    /// ```
    ///
    /// The subgroup relation turns each squared coordinate into one F_{p^4} squaring plus linear terms.
    #[must_use]
    pub fn cyclotomic_square(&self) -> Self {
        // Unpack the six F_{p^2} coefficients into the F_{p^4} pairs.
        //
        //     z0 = w^0, z1 = w^3   (A)
        //     z2 = w^1, z3 = w^4   (B)
        //     z4 = w^2, z5 = w^5   (C)
        let z0 = self.c0.c0;
        let z4 = self.c0.c1;
        let z3 = self.c0.c2;
        let z2 = self.c1.c0;
        let z1 = self.c1.c1;
        let z5 = self.c1.c2;

        // A' = 3 A^2 - 2 conj(A)
        let (t0, t1) = Self::fp4_square(&z0, &z1);
        let z0 = (t0 - z0).double() + t0;
        let z1 = (t1 + z1).double() + t1;

        // C' = 3 B^2 - 2 conj(C)
        let (t0, t1) = Self::fp4_square(&z2, &z3);
        let (t2, t3) = Self::fp4_square(&z4, &z5);
        let z4 = (t0 - z4).double() + t0;
        let z5 = (t1 + z5).double() + t1;

        // B' = 3 xi C^2 + 2 conj(B), where multiplying C^2 by s shifts its halves
        let t0 = t3.mul_by_nonresidue();
        let z2 = (t0 + z2).double() + t0;
        let z3 = (t2 - z3).double() + t2;

        Self::new(Fp6::new(z0, z4, z3), Fp6::new(z2, z1, z5))
    }

    /// Squares a + b * s in F_{p^4} = F_{p^2}\[s\] / (s^2 - xi).
    ///
    /// # Returns
    ///
    /// The coefficients of 1 and of s in the square.
    fn fp4_square(a: &Fp2, b: &Fp2) -> (Fp2, Fp2) {
        // (a + b s)^2 = (a^2 + xi b^2) + ((a + b)^2 - a^2 - b^2) s
        let a2 = a.square();
        let b2 = b.square();
        let c0 = b2.mul_by_nonresidue() + a2;
        let c1 = (*a + b).square() - a2 - b2;
        (c0, c1)
    }

    /// Returns self + rhs.
    #[inline]
    fn add_impl(&self, rhs: &Self) -> Self {
        Self::new(self.c0 + rhs.c0, self.c1 + rhs.c1)
    }

    /// Returns self - rhs.
    #[inline]
    fn sub_impl(&self, rhs: &Self) -> Self {
        Self::new(self.c0 - rhs.c0, self.c1 - rhs.c1)
    }

    /// Returns self * rhs.
    #[inline]
    fn mul_impl(&self, rhs: &Self) -> Self {
        // Karatsuba over w^2 = v: three F_{p^6} products.
        //
        //     (a0 + a1 w)(b0 + b1 w) = (a0 b0 + v a1 b1) + ((a0 + a1)(b0 + b1) - a0 b0 - a1 b1) w
        let aa = self.c0 * rhs.c0;
        let bb = self.c1 * rhs.c1;
        let c1 = (self.c0 + self.c1) * (rhs.c0 + rhs.c1) - aa - bb;
        let c0 = bb.mul_by_nonresidue() + aa;
        Self::new(c0, c1)
    }

    /// Returns -self.
    #[inline]
    fn neg_impl(&self) -> Self {
        Self::new(-self.c0, -self.c1)
    }
}

impl fmt::Debug for Fp12 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:?}) + ({:?}) * w", self.c0, self.c1)
    }
}

impl Add for Fp12 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        self.add_impl(&rhs)
    }
}

impl Add<&Self> for Fp12 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self {
        self.add_impl(rhs)
    }
}

impl Add<&Fp12> for &Fp12 {
    type Output = Fp12;

    #[inline]
    fn add(self, rhs: &Fp12) -> Fp12 {
        self.add_impl(rhs)
    }
}

impl AddAssign for Fp12 {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add_impl(&rhs);
    }
}

impl AddAssign<&Self> for Fp12 {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        *self = self.add_impl(rhs);
    }
}

impl Sub for Fp12 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        self.sub_impl(&rhs)
    }
}

impl Sub<&Self> for Fp12 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &Self) -> Self {
        self.sub_impl(rhs)
    }
}

impl Sub<&Fp12> for &Fp12 {
    type Output = Fp12;

    #[inline]
    fn sub(self, rhs: &Fp12) -> Fp12 {
        self.sub_impl(rhs)
    }
}

impl SubAssign for Fp12 {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub_impl(&rhs);
    }
}

impl SubAssign<&Self> for Fp12 {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        *self = self.sub_impl(rhs);
    }
}

impl Mul for Fp12 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        self.mul_impl(&rhs)
    }
}

impl Mul<&Self> for Fp12 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Self) -> Self {
        self.mul_impl(rhs)
    }
}

impl Mul<&Fp12> for &Fp12 {
    type Output = Fp12;

    #[inline]
    fn mul(self, rhs: &Fp12) -> Fp12 {
        self.mul_impl(rhs)
    }
}

impl MulAssign for Fp12 {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul_impl(&rhs);
    }
}

impl MulAssign<&Self> for Fp12 {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        *self = self.mul_impl(rhs);
    }
}

impl Neg for Fp12 {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        self.neg_impl()
    }
}

impl Neg for &Fp12 {
    type Output = Fp12;

    #[inline]
    fn neg(self) -> Fp12 {
        self.neg_impl()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{fp2::tests::arb_fp2, fp6::tests::arb_fp6};

    /// Uniform elements of F_{p^12}.
    pub(crate) fn arb_fp12() -> impl Strategy<Value = Fp12> {
        (arb_fp6(), arb_fp6()).prop_map(|(c0, c1)| Fp12::new(c0, c1))
    }

    /// Maps a nonzero element into the cyclotomic subgroup with the easy exponent (p^6 - 1)(p^2 + 1).
    fn into_cyclotomic_subgroup(a: &Fp12) -> Fp12 {
        // x^{p^6 - 1} = conj(x) / x
        let t = a.conjugate() * a.invert().unwrap();
        // t^{p^2 + 1} = frob(frob(t)) * t
        t.frobenius_map().frobenius_map() * t
    }

    #[test]
    fn w_squared_is_v() {
        let w = Fp12::new(Fp6::ZERO, Fp6::ONE);
        let v = Fp12::new(Fp6::new(Fp2::ZERO, Fp2::ONE, Fp2::ZERO), Fp6::ZERO);
        assert_eq!(w.square(), v);
    }

    proptest! {
        #[test]
        fn field_axioms_hold(a in arb_fp12(), b in arb_fp12(), c in arb_fp12()) {
            // Associativity and commutativity of the product, then distributivity.
            prop_assert_eq!((a * b) * c, a * (b * c));
            prop_assert_eq!(a * b, b * a);
            prop_assert_eq!(a * (b + c), a * b + a * c);
            // The dedicated squaring agrees with the generic product.
            prop_assert_eq!(a.square(), a * a);
        }

        #[test]
        fn inverse_is_multiplicative(a in arb_fp12()) {
            prop_assume!(!a.is_zero());
            prop_assert_eq!(a * a.invert().unwrap(), Fp12::ONE);
        }

        #[test]
        fn sparse_line_product_matches_dense(
            a in arb_fp12(), b0 in arb_fp2(), b1 in arb_fp2(), b4 in arb_fp2()
        ) {
            // Positions 0, 1, 4 are 1, v, and v w.
            let line = Fp12::new(
                Fp6::new(b0, b1, Fp2::ZERO),
                Fp6::new(Fp2::ZERO, b4, Fp2::ZERO),
            );
            prop_assert_eq!(a.mul_by_014(&b0, &b1, &b4), a * line);
        }

        #[test]
        fn frobenius_is_a_ring_morphism_of_order_twelve(a in arb_fp12(), b in arb_fp12()) {
            // x -> x^p respects products.
            prop_assert_eq!((a * b).frobenius_map(), a.frobenius_map() * b.frobenius_map());
            // Twelve applications give x^{p^12} = x on F_{p^12}.
            let mut image = a;
            for _ in 0..12 {
                image = image.frobenius_map();
            }
            prop_assert_eq!(image, a);
        }

        #[test]
        fn conjugate_is_the_sixth_frobenius_power(a in arb_fp12()) {
            // x^{p^6} flips the sign of the w coefficient, which is conjugation.
            let mut image = a;
            for _ in 0..6 {
                image = image.frobenius_map();
            }
            prop_assert_eq!(image, a.conjugate());
        }

        #[test]
        fn cyclotomic_square_matches_generic_square(a in arb_fp12()) {
            prop_assume!(!a.is_zero());
            let g = into_cyclotomic_subgroup(&a);
            prop_assert_eq!(g.cyclotomic_square(), g.square());
            // Inside the subgroup the conjugate is the inverse.
            prop_assert_eq!(g * g.conjugate(), Fp12::ONE);
        }
    }
}
