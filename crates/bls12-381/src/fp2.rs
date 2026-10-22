//! The quadratic extension F_{p^2} = F_p\[u\] / (u^2 + 1).
//!
//! Since p = 3 mod 4, -1 is not a square in F_p, so u^2 = -1 defines a field.
//! G2 coordinates live here, and it is the base of the degree-12 tower.

use std::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use crate::Fp;

/// The element 1 / 2 = (p + 1) / 2, in Montgomery form.
const HALF: Fp = Fp::from_montgomery([
    0x1804_0000_0001_5554,
    0x8550_0005_3ab0_0001,
    0x633c_b57c_253c_276f,
    0x6e22_d1ec_31eb_b502,
    0xd391_6126_f2d1_4ca2,
    0x17fb_b857_1a00_6596,
]);

/// The exponent (p - 3) / 4, as little-endian limbs.
///
/// For a nonzero t, y = t^{(p-3)/4} gives both t y = t^{(p+1)/4}, a root candidate, and t y^2, the Legendre symbol.
const P_MINUS_3_OVER_4: [u64; 6] = [
    0xee7f_bfff_ffff_eaaa,
    0x07aa_ffff_ac54_ffff,
    0xd9cc_34a8_3dac_3d89,
    0xd91d_d2e1_3ce1_44af,
    0x92c6_e9ed_90d2_eb35,
    0x0680_447a_8e5f_f9a6,
];

/// An element c0 + c1 * u of F_{p^2}, where u^2 = -1.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Fp2 {
    /// The coefficient of 1.
    pub c0: Fp,
    /// The coefficient of u.
    pub c1: Fp,
}

impl Fp2 {
    /// The additive identity.
    pub const ZERO: Self = Self::new(Fp::ZERO, Fp::ZERO);

    /// The multiplicative identity.
    pub const ONE: Self = Self::new(Fp::ONE, Fp::ZERO);

    /// Builds c0 + c1 * u.
    #[must_use]
    pub const fn new(c0: Fp, c1: Fp) -> Self {
        Self { c0, c1 }
    }

    /// Whether the element is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() & self.c1.is_zero()
    }

    /// Returns 2 * self.
    #[must_use]
    pub fn double(&self) -> Self {
        Self::new(self.c0.double(), self.c1.double())
    }

    /// Returns self^2.
    #[must_use]
    pub fn square(&self) -> Self {
        // Complex squaring with two base-field products instead of three.
        //
        //     (a + b u)^2 = (a^2 - b^2) + 2ab u = (a + b)(a - b) + 2ab u
        let a = self.c0;
        let b = self.c1;
        Self::new((a + b) * (a - b), (a * b).double())
    }

    /// Returns the conjugate c0 - c1 * u.
    ///
    /// Conjugation is the Frobenius map x -> x^p on this field, since u^p = -u when p = 3 mod 4.
    #[must_use]
    pub fn conjugate(&self) -> Self {
        Self::new(self.c0, -self.c1)
    }

    /// Multiplies by the non-residue xi = 1 + u that defines the sextic tower above this field.
    #[must_use]
    pub fn mul_by_nonresidue(&self) -> Self {
        // (a + b u)(1 + u) = (a - b) + (a + b) u, with no multiplication at all.
        Self::new(self.c0 - self.c1, self.c0 + self.c1)
    }

    /// Multiplies both coefficients by a base-field element.
    #[must_use]
    pub fn mul_by_fp(&self, scalar: &Fp) -> Self {
        Self::new(self.c0 * scalar, self.c1 * scalar)
    }

    /// Returns the norm c0^2 + c1^2, the product of the element with its conjugate.
    #[must_use]
    pub fn norm(&self) -> Fp {
        self.c0.square() + self.c1.square()
    }

    /// Computes the multiplicative inverse.
    ///
    /// # Returns
    ///
    /// The inverse, or nothing for zero.
    #[must_use]
    pub fn invert(&self) -> Option<Self> {
        // Multiply by the conjugate to land in F_p, invert there, then scale back.
        //
        //     1 / (a + b u) = (a - b u) / (a^2 + b^2)
        let inverse_norm = self.norm().invert()?;
        Some(Self::new(self.c0 * inverse_norm, -(self.c1 * inverse_norm)))
    }

    /// Raises the element to a power given as little-endian limbs.
    ///
    /// The running time depends on the exponent only.
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

    /// Computes a square root.
    ///
    /// The running time depends on the input.
    /// Callers only pass public values, such as points of a hashed message.
    ///
    /// # Returns
    ///
    /// A root, or nothing when the element is not a square.
    ///
    /// # Algorithm
    ///
    /// The "complex method" for p = 3 mod 4, Scott, eprint 2012/685 section 3.
    /// Write the root as x0 + x1 u and expand its square:
    ///
    /// ```text
    ///     x0^2 - x1^2 = a,    2 x0 x1 = b,    x0^2 + x1^2 = sqrt(a^2 + b^2) = s
    ///     =>  x0^2 = t = (a + s) / 2,    x1 = b / (2 x0)
    /// ```
    ///
    /// One base-field power y = t^{(p-3)/4} serves every remaining step:
    ///
    /// ```text
    ///     t square    : t y^2 = 1,   x0 = t y,         x1 = b y / 2
    ///     t non-square: t y^2 = -1,  x0 = b y / 2,     x1 = -t y
    /// ```
    ///
    /// In the second case (b y / 2)^2 = -b^2 / (4 t) = (a - s) / 2, the conjugate choice of sign.
    /// Two exponentiations in total, and no inversion.
    #[must_use]
    pub fn sqrt(&self) -> Option<Self> {
        let a = self.c0;
        let b = self.c1;

        // A base-field input has a root either in F_p or in u * F_p.
        //
        //     a square in F_p : root sqrt(a)
        //     otherwise       : -a is a square, and (sqrt(-a) u)^2 = -(-a) = a
        if b.is_zero() {
            return match a.sqrt() {
                Some(root) => Some(Self::new(root, Fp::ZERO)),
                None => (-a).sqrt().map(|root| Self::new(Fp::ZERO, root)),
            };
        }

        // Exponentiation 1: the norm of a square is a square in F_p.
        // A non-square norm proves the input has no root.
        let norm_root = self.norm().sqrt()?;

        // Exponentiation 2: y = t^{(p-3)/4}, so that t y^2 = t^{(p-1)/2} is the Legendre symbol of t.
        // t is nonzero: (a + s)(a - s) = a^2 - s^2 = -b^2 is nonzero.
        let t = (a + norm_root) * HALF;
        let y = t.pow_vartime(&P_MINUS_3_OVER_4);
        let t_y = t * y;
        let half_b_y = b * y * HALF;
        let root = if t_y * y == Fp::ONE {
            Self::new(t_y, half_b_y)
        } else {
            Self::new(half_b_y, -t_y)
        };

        // The final check also rejects any input the shortcuts above misjudge.
        (root.square() == *self).then_some(root)
    }

    /// Whether the element exceeds its own negation in the ZCash encoding order.
    ///
    /// The order compares the u coefficient first and falls back to the constant one when it is zero.
    #[must_use]
    pub fn is_lexicographically_largest(&self) -> bool {
        self.c1.is_lexicographically_largest()
            || (self.c1.is_zero() && self.c0.is_lexicographically_largest())
    }

    /// The sgn0 function of RFC 9380 section 4.1 for an extension of degree two.
    ///
    /// It is the parity of the constant coefficient, or of the u coefficient when the constant one is zero.
    pub(crate) fn sgn0(&self) -> bool {
        // The constant coefficient decides unless it is zero.
        let sign_0 = self.c0.is_odd();
        let zero_0 = self.c0.is_zero();
        let sign_1 = self.c1.is_odd();
        sign_0 || (zero_0 && sign_1)
    }

    /// Picks the second element when the flag is set, the first otherwise, without branching.
    pub(crate) fn conditional_select(a: &Self, b: &Self, choice: bool) -> Self {
        // Select both coefficients with the same flag.
        Self::new(
            Fp::conditional_select(&a.c0, &b.c0, choice),
            Fp::conditional_select(&a.c1, &b.c1, choice),
        )
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
        // Schoolbook with lazy reduction: four limb products, but only two reductions.
        // Reductions dominate, so this beats Karatsuba's three full products.
        //
        //     (a0 + a1 u)(b0 + b1 u) = (a0 b0 + (-a1) b1) + (a0 b1 + a1 b0) u
        Self::new(
            Fp::sum_of_products([self.c0, -self.c1], [rhs.c0, rhs.c1]),
            Fp::sum_of_products([self.c0, self.c1], [rhs.c1, rhs.c0]),
        )
    }

    /// Returns -self.
    #[inline]
    fn neg_impl(&self) -> Self {
        Self::new(-self.c0, -self.c1)
    }
}

impl fmt::Debug for Fp2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Fp2 {
    /// Renders both coefficients in hex, the constant one first.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} + {} * u", self.c0, self.c1)
    }
}

impl Add for Fp2 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        self.add_impl(&rhs)
    }
}

impl Add<&Self> for Fp2 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self {
        self.add_impl(rhs)
    }
}

impl Add<&Fp2> for &Fp2 {
    type Output = Fp2;

    #[inline]
    fn add(self, rhs: &Fp2) -> Fp2 {
        self.add_impl(rhs)
    }
}

impl AddAssign for Fp2 {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add_impl(&rhs);
    }
}

impl AddAssign<&Self> for Fp2 {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        *self = self.add_impl(rhs);
    }
}

impl Sub for Fp2 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        self.sub_impl(&rhs)
    }
}

impl Sub<&Self> for Fp2 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &Self) -> Self {
        self.sub_impl(rhs)
    }
}

impl Sub<&Fp2> for &Fp2 {
    type Output = Fp2;

    #[inline]
    fn sub(self, rhs: &Fp2) -> Fp2 {
        self.sub_impl(rhs)
    }
}

impl SubAssign for Fp2 {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub_impl(&rhs);
    }
}

impl SubAssign<&Self> for Fp2 {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        *self = self.sub_impl(rhs);
    }
}

impl Mul for Fp2 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        self.mul_impl(&rhs)
    }
}

impl Mul<&Self> for Fp2 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Self) -> Self {
        self.mul_impl(rhs)
    }
}

impl Mul<&Fp2> for &Fp2 {
    type Output = Fp2;

    #[inline]
    fn mul(self, rhs: &Fp2) -> Fp2 {
        self.mul_impl(rhs)
    }
}

impl MulAssign for Fp2 {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul_impl(&rhs);
    }
}

impl MulAssign<&Self> for Fp2 {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        *self = self.mul_impl(rhs);
    }
}

impl Neg for Fp2 {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        self.neg_impl()
    }
}

impl Neg for &Fp2 {
    type Output = Fp2;

    #[inline]
    fn neg(self) -> Fp2 {
        self.neg_impl()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::fp::tests::arb_fp;

    /// Uniform elements of F_{p^2}.
    pub(crate) fn arb_fp2() -> impl Strategy<Value = Fp2> {
        (arb_fp(), arb_fp()).prop_map(|(c0, c1)| Fp2::new(c0, c1))
    }

    #[test]
    fn u_squares_to_minus_one() {
        // The defining relation of the extension.
        let u = Fp2::new(Fp::ZERO, Fp::ONE);
        assert_eq!(u.square(), -Fp2::ONE);
    }

    #[test]
    fn base_field_non_square_has_root_on_the_u_axis() {
        // -1 is not a square in F_p, but u is its root in F_{p^2}.
        let root = (-Fp2::ONE).sqrt().unwrap();
        assert_eq!(root.square(), -Fp2::ONE);
        assert!(root.c0.is_zero());
    }

    #[test]
    fn non_residue_has_no_root() {
        // xi = 1 + u is the tower's non-residue, so it cannot be a square.
        let xi = Fp2::new(Fp::ONE, Fp::ONE);
        assert_eq!(xi.sqrt(), None);
    }

    #[test]
    fn sign_falls_back_to_the_u_coefficient() {
        // RFC 9380 section 4.1: with c0 = 0 the sign is the parity of c1.
        assert!(Fp2::new(Fp::ZERO, Fp::ONE).sgn0());
        assert!(!Fp2::new(Fp::ZERO, Fp::from_u64(2)).sgn0());
        // A nonzero c0 decides on its own: 2 is even whatever c1 is.
        assert!(!Fp2::new(Fp::from_u64(2), Fp::ONE).sgn0());
    }

    proptest! {
        #[test]
        fn field_axioms_hold(a in arb_fp2(), b in arb_fp2(), c in arb_fp2()) {
            // Associativity and commutativity of the product, then distributivity.
            prop_assert_eq!((a * b) * c, a * (b * c));
            prop_assert_eq!(a * b, b * a);
            prop_assert_eq!(a * (b + c), a * b + a * c);
            // The dedicated squaring agrees with the generic product.
            prop_assert_eq!(a.square(), a * a);
            // Subtraction undoes addition.
            prop_assert_eq!(a - b + b, a);
        }

        #[test]
        fn product_matches_schoolbook(a in arb_fp2(), b in arb_fp2()) {
            // Reference: four products and u^2 = -1.
            let expected = Fp2::new(a.c0 * b.c0 - a.c1 * b.c1, a.c0 * b.c1 + a.c1 * b.c0);
            prop_assert_eq!(a * b, expected);
        }

        #[test]
        fn inverse_is_multiplicative(a in arb_fp2()) {
            prop_assume!(!a.is_zero());
            prop_assert_eq!(a * a.invert().unwrap(), Fp2::ONE);
        }

        #[test]
        fn conjugation_is_the_frobenius(a in arb_fp2()) {
            // Raising to p, with p given by its limbs, equals conjugation.
            let p = [
                0xb9fe_ffff_ffff_aaab, 0x1eab_fffe_b153_ffff, 0x6730_d2a0_f6b0_f624,
                0x6477_4b84_f385_12bf, 0x4b1b_a7b6_434b_acd7, 0x1a01_11ea_397f_e69a,
            ];
            prop_assert_eq!(a.pow_vartime(&p), a.conjugate());
        }

        #[test]
        fn squares_have_roots(a in arb_fp2()) {
            let root = a.square().sqrt().unwrap();
            prop_assert_eq!(root.square(), a.square());
        }

        #[test]
        fn nonresidue_product_matches_generic(a in arb_fp2()) {
            prop_assert_eq!(a.mul_by_nonresidue(), a * Fp2::new(Fp::ONE, Fp::ONE));
        }
    }
}
