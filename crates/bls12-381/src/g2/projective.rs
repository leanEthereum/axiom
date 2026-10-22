//! G2 points in homogeneous projective coordinates, with complete addition formulas.
//!
//! A point (X : Y : Z) stands for the affine point (X / Z, Y / Z).
//! Z = 0 is the point at infinity.
//! The formulas are those of Renes, Costello, and Batina, "Complete addition formulas for prime order elliptic curves", eprint 2015/1060, specialized to a = 0.
//! Complete means one formula handles every input, including doubling and the identity.
//! There is no branch to leak timing, and no exceptional case to forget.

use std::{
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use super::{B, G2Affine, PSI_X, PSI_Y, PSI2_X};
use crate::{
    BLS_X, Fp2, Scalar, hash_to_curve,
    msm::{self, PippengerGroup},
};

/// A point of E'(F_{p^2}) in homogeneous projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct G2Projective {
    /// The X coordinate.
    pub(crate) x: Fp2,
    /// The Y coordinate.
    pub(crate) y: Fp2,
    /// The Z coordinate, zero exactly at infinity.
    pub(crate) z: Fp2,
}

impl G2Projective {
    /// The point at infinity (0 : 1 : 0).
    pub const IDENTITY: Self = Self {
        x: Fp2::ZERO,
        y: Fp2::ONE,
        z: Fp2::ZERO,
    };

    /// The standard generator of G2.
    pub const GENERATOR: Self = Self {
        x: G2Affine::GENERATOR.x,
        y: G2Affine::GENERATOR.y,
        z: Fp2::ONE,
    };

    /// Builds a point from projective coordinates the caller knows to be on the curve.
    pub(crate) const fn from_coordinates(x: Fp2, y: Fp2, z: Fp2) -> Self {
        Self { x, y, z }
    }

    /// Hashes a message to a point of G2 with the suite BLS12381G2_XMD:SHA-256_SSWU_RO_.
    ///
    /// This is hash_to_curve of RFC 9380 section 3, with the parameters of section 8.8.2.
    /// The domain separation tag binds the output to one protocol.
    /// The running time depends on the message, which must be public.
    #[must_use]
    pub fn hash_to_curve(message: &[u8], dst: &[u8]) -> Self {
        hash_to_curve::hash_to_g2(message, dst)
    }

    /// Whether this is the point at infinity.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.z.is_zero()
    }

    /// Whether the point satisfies the projective curve equation Y^2 Z = X^3 + 4 Z^3.
    #[must_use]
    pub fn is_on_curve(&self) -> bool {
        // Multiply y^2 = x^3 + 4 through by Z^3.
        self.y.square() * self.z == self.x.square() * self.x + self.z.square() * self.z * B
            || self.is_identity()
    }

    /// Returns 2 * self.
    ///
    /// Algorithm 9 of eprint 2015/1060: 6 multiplications, 2 squarings, 1 multiplication by 3b.
    #[must_use]
    pub fn double(&self) -> Self {
        // Phase 1: the squares the formula reuses.
        //
        //     t0 = Y^2,  t1 = Y Z,  t2 = 3b Z^2,  X3 = 24 b Y^2 Z^2
        let t0 = self.y.square();
        let z3 = t0.double().double().double();
        let t1 = self.y * self.z;
        let t2 = Self::mul_by_3b(&self.z.square());
        let x3 = t2 * z3;
        // Phase 2: Y3 = (Y^2 - 9b Z^2)(Y^2 + 3b Z^2) + 24 b Y^2 Z^2 and Z3 = 8 Y^3 Z.
        let y3 = t0 + t2;
        let z3 = t1 * z3;
        let t1 = t2.double();
        let t2 = t1 + t2;
        let t0 = t0 - t2;
        let y3 = t0 * y3 + x3;
        // Phase 3: X3 = 2 X Y (Y^2 - 9b Z^2).
        let t1 = self.x * self.y;
        let x3 = (t0 * t1).double();
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// The endomorphism psi = twist o Frobenius o untwist, which acts on G2 as multiplication by p.
    ///
    /// RFC 9380 appendix G.3 gives it on affine coordinates:
    ///
    /// ```text
    ///     psi(x, y) = (c_x * conj(x), c_y * conj(y))
    /// ```
    ///
    /// Projective coordinates follow by conjugating Z too, since conjugation is a field automorphism.
    #[must_use]
    pub fn psi(&self) -> Self {
        // Conjugate every coordinate, then rescale x and y by the twist constants.
        Self {
            x: self.x.conjugate() * PSI_X,
            y: self.y.conjugate() * PSI_Y,
            z: self.z.conjugate(),
        }
    }

    /// The endomorphism psi applied twice, computed directly.
    ///
    /// Two conjugations cancel, and the product of the scalings collapses to a cube root of unity on x and -1 on y.
    #[must_use]
    pub fn psi2(&self) -> Self {
        // The double conjugation cancels, leaving one scaling of x and a sign flip of y.
        Self {
            x: self.x.mul_by_fp(&PSI2_X),
            y: -self.y,
            z: self.z,
        }
    }

    /// Maps any point of E'(F_{p^2}) into G2 by multiplying with the effective cofactor h_eff.
    ///
    /// # Algorithm
    ///
    /// Budroni and Pintore, "Efficient hash maps to G2 on BLS curves", section 4.1, as written in RFC 9380 appendix G.3.
    /// It evaluates a polynomial in psi instead of a 636-bit scalar multiplication:
    ///
    /// ```text
    ///     h_eff P = [x^2 - x - 1] P + [x - 1] psi(P) + psi^2(2P)
    /// ```
    #[must_use]
    pub fn clear_cofactor(&self) -> Self {
        // t1 = [x] P
        let t1 = self.mul_by_x();
        // t2 = psi(P)
        let t2 = self.psi();
        // t3 = psi^2(2P) - psi(P)
        let t3 = self.double().psi2() - t2;
        // t2 = [x] (x P + psi(P)) = [x^2] P + [x] psi(P)
        let t2 = (t1 + t2).mul_by_x();
        // t3 = psi^2(2P) - psi(P) + [x^2] P + [x] psi(P) - [x] P - P
        t3 + t2 - t1 - self
    }

    /// Multiplies by 3b' = 12 + 12u with additions only.
    fn mul_by_3b(value: &Fp2) -> Fp2 {
        // 12 v = 3 * 4v, then the factor 1 + u is the tower's non-residue product.
        let four = value.double().double();
        (four.double() + four).mul_by_nonresidue()
    }

    /// Multiplies by the curve parameter x = -0xd201000000010000.
    ///
    /// The scalar is public, so the variable-time chain leaks nothing.
    pub(crate) fn mul_by_x(&self) -> Self {
        // Double-and-add over the 64 bits of |x|, then negate for the sign of x.
        let mut acc = Self::IDENTITY;
        for bit in (0..64).rev() {
            acc = acc.double();
            if (BLS_X >> bit) & 1 == 1 {
                acc += self;
            }
        }
        -acc
    }

    /// Multiplies by a scalar in time that depends on the scalar.
    ///
    /// Use it only with public scalars, such as batch-verification coefficients.
    #[must_use]
    pub fn mul_vartime(&self, scalar: &Scalar) -> Self {
        let mut acc = Self::IDENTITY;
        let mut started = false;
        // Left-to-right double-and-add, skipping the leading zero bits.
        for limb in scalar.to_canonical().iter().rev() {
            for bit in (0..64).rev() {
                let set = (limb >> bit) & 1 == 1;
                if started {
                    acc = acc.double();
                }
                if set {
                    acc += self;
                    started = true;
                }
            }
        }
        acc
    }

    /// Computes sum_i k_i P_i over paired points and scalars, with Pippenger's bucket method.
    ///
    /// The running time depends on the scalars, which must be public.
    ///
    /// # Panics
    ///
    /// Panics when the two slices differ in length.
    #[must_use]
    pub fn multi_exp(points: &[G2Affine], scalars: &[Scalar]) -> Self {
        msm::multi_exp(points, scalars)
    }

    /// Converts many points to affine form with a single field inversion.
    #[must_use]
    pub fn batch_normalize(points: &[Self]) -> Vec<G2Affine> {
        // Phase 1: running products of the nonzero Z coordinates.
        let mut prefixes = Vec::with_capacity(points.len());
        let mut product = Fp2::ONE;
        for point in points {
            prefixes.push(product);
            if !point.is_identity() {
                product *= point.z;
            }
        }

        // Phase 2: one inversion of the total product, nonzero by construction.
        let mut inverse = product.invert().unwrap_or(Fp2::ZERO);

        // Phase 3: walk back, reading off each 1 / Z and peeling it from the inverse.
        let mut affine = vec![G2Affine::IDENTITY; points.len()];
        for ((out, point), prefix) in affine.iter_mut().zip(points).zip(prefixes).rev() {
            if point.is_identity() {
                continue;
            }
            let z_inverse = inverse * prefix;
            inverse *= point.z;
            *out = G2Affine {
                x: point.x * z_inverse,
                y: point.y * z_inverse,
                infinity: false,
            };
        }
        affine
    }

    /// Picks the second point when the flag is set, the first otherwise, without branching.
    pub(crate) fn conditional_select(a: &Self, b: &Self, choice: bool) -> Self {
        // Select each coordinate with the same mask.
        Self {
            x: Fp2::conditional_select(&a.x, &b.x, choice),
            y: Fp2::conditional_select(&a.y, &b.y, choice),
            z: Fp2::conditional_select(&a.z, &b.z, choice),
        }
    }

    /// Multiplies by a scalar in constant time.
    ///
    /// # Algorithm
    ///
    /// Fixed 4-bit windows over all 256 bits of the canonical scalar.
    /// Each window costs four doublings and one addition of a table entry.
    /// The entry is read with a masked scan of the whole table, so memory access does not depend on the scalar.
    fn multiply(&self, scalar: &Scalar) -> Self {
        // Phase 1: table[i] = i * P for i in 0..16.
        let mut table = [Self::IDENTITY; 16];
        for i in 1..16 {
            table[i] = table[i - 1] + self;
        }

        // Phase 2: consume the scalar four bits at a time, most significant first.
        let mut acc = Self::IDENTITY;
        for byte in scalar.to_bytes_be() {
            for window in [byte >> 4, byte & 0x0f] {
                acc = acc.double().double().double().double();
                let mut entry = Self::IDENTITY;
                for (index, candidate) in (0_u8..).zip(&table) {
                    entry = Self::conditional_select(&entry, candidate, index == window);
                }
                acc += entry;
            }
        }
        acc
    }

    /// Returns self + rhs.
    ///
    /// Algorithm 7 of eprint 2015/1060: 12 multiplications, 2 multiplications by 3b.
    fn add_impl(&self, rhs: &Self) -> Self {
        // Phase 1: the three coordinate products.
        let t0 = self.x * rhs.x;
        let t1 = self.y * rhs.y;
        let t2 = self.z * rhs.z;
        // Phase 2: the three cross sums, each from one product by Karatsuba.
        //
        //     t3 = X1 Y2 + X2 Y1,  t4 = Y1 Z2 + Y2 Z1,  y3 = X1 Z2 + X2 Z1
        let t3 = (self.x + self.y) * (rhs.x + rhs.y) - (t0 + t1);
        let t4 = (self.y + self.z) * (rhs.y + rhs.z) - (t1 + t2);
        let y3 = (self.x + self.z) * (rhs.x + rhs.z) - (t0 + t2);
        // Phase 3: scale by 3 and 3b, folding in the curve equation y^2 = x^3 + b.
        //
        //     t0 = 3 X1 X2,  z3 = Y1 Y2 + 3b Z1 Z2,  t1 = Y1 Y2 - 3b Z1 Z2
        let t0 = t0.double() + t0;
        let t2 = Self::mul_by_3b(&t2);
        let z3 = t1 + t2;
        let t1 = t1 - t2;
        let y3 = Self::mul_by_3b(&y3);
        // Phase 4: assemble the sum from the scaled terms.
        let x3 = t3 * t1 - t4 * y3;
        let y3 = t1 * z3 + y3 * t0;
        let z3 = z3 * t4 + t0 * t3;
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Returns self + rhs for an affine rhs.
    ///
    /// Algorithm 8 of eprint 2015/1060: 11 multiplications, 2 multiplications by 3b.
    /// The formula assumes Z2 = 1, which fails at infinity, so that case selects self instead.
    fn add_mixed_impl(&self, rhs: &G2Affine) -> Self {
        // Phase 1: the coordinate products, with Z2 = 1 implicit.
        let t0 = self.x * rhs.x;
        let t1 = self.y * rhs.y;
        // Phase 2: the cross sums.
        //
        //     t3 = X1 Y2 + X2 Y1,  t4 = Y1 + Y2 Z1,  y3 = X1 + X2 Z1
        let t3 = (rhs.x + rhs.y) * (self.x + self.y) - (t0 + t1);
        let t4 = rhs.y * self.z + self.y;
        let y3 = rhs.x * self.z + self.x;
        // Phase 3: scale by 3 and 3b, as in the full addition.
        let t0 = t0.double() + t0;
        let t2 = Self::mul_by_3b(&self.z);
        let z3 = t1 + t2;
        let t1 = t1 - t2;
        let y3 = Self::mul_by_3b(&y3);
        // Phase 4: assemble the sum.
        let x3 = t3 * t1 - t4 * y3;
        let y3 = t1 * z3 + y3 * t0;
        let z3 = z3 * t4 + t0 * t3;
        let sum = Self {
            x: x3,
            y: y3,
            z: z3,
        };
        // An affine identity has no Z = 1 form, so the sum is replaced by self.
        Self::conditional_select(&sum, self, rhs.infinity)
    }

    /// Returns self - rhs.
    fn sub_impl(&self, rhs: &Self) -> Self {
        self.add_impl(&rhs.neg_impl())
    }

    /// Returns -self.
    fn neg_impl(&self) -> Self {
        // -(X : Y : Z) = (X : -Y : Z), the reflection across the x-axis.
        Self {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }
}

impl Default for G2Projective {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl PartialEq for G2Projective {
    fn eq(&self, other: &Self) -> bool {
        // Two finite points are equal when their affine coordinates agree:
        //
        //     X1 / Z1 = X2 / Z2  <=>  X1 Z2 = X2 Z1, and likewise for Y
        let self_identity = self.is_identity();
        let other_identity = other.is_identity();
        let same_affine =
            self.x * other.z == other.x * self.z && self.y * other.z == other.y * self.z;
        (self_identity && other_identity) || (!self_identity && !other_identity && same_affine)
    }
}

impl Eq for G2Projective {}

impl From<&G2Affine> for G2Projective {
    fn from(point: &G2Affine) -> Self {
        // (x, y) lifts to (x : y : 1).
        // Infinity lifts to (0 : 1 : 0).
        Self {
            x: point.x,
            y: point.y,
            z: Fp2::conditional_select(&Fp2::ONE, &Fp2::ZERO, point.infinity),
        }
    }
}

impl From<G2Affine> for G2Projective {
    fn from(point: G2Affine) -> Self {
        Self::from(&point)
    }
}

impl Add<&G2Affine> for G2Projective {
    type Output = Self;

    fn add(self, rhs: &G2Affine) -> Self {
        self.add_mixed_impl(rhs)
    }
}

impl Add<G2Affine> for G2Projective {
    type Output = Self;

    fn add(self, rhs: G2Affine) -> Self {
        self.add_mixed_impl(&rhs)
    }
}

impl AddAssign<&G2Affine> for G2Projective {
    fn add_assign(&mut self, rhs: &G2Affine) {
        *self = self.add_mixed_impl(rhs);
    }
}

impl AddAssign<G2Affine> for G2Projective {
    fn add_assign(&mut self, rhs: G2Affine) {
        *self = self.add_mixed_impl(&rhs);
    }
}

impl Mul<&Scalar> for &G2Projective {
    type Output = G2Projective;

    fn mul(self, scalar: &Scalar) -> G2Projective {
        self.multiply(scalar)
    }
}

impl Mul<&Scalar> for G2Projective {
    type Output = Self;

    fn mul(self, scalar: &Scalar) -> Self {
        self.multiply(scalar)
    }
}

impl Mul<Scalar> for G2Projective {
    type Output = Self;

    fn mul(self, scalar: Scalar) -> Self {
        self.multiply(&scalar)
    }
}

impl MulAssign<&Scalar> for G2Projective {
    fn mul_assign(&mut self, scalar: &Scalar) {
        *self = self.multiply(scalar);
    }
}

impl MulAssign<Scalar> for G2Projective {
    fn mul_assign(&mut self, scalar: Scalar) {
        *self = self.multiply(&scalar);
    }
}

impl Sum for G2Projective {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::IDENTITY, |acc, point| acc + point)
    }
}

impl<'a> Sum<&'a Self> for G2Projective {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::IDENTITY, |acc, point| acc + point)
    }
}

impl PippengerGroup for G2Projective {
    type Affine = G2Affine;

    const NEUTRAL: Self = Self::IDENTITY;

    fn double_point(&self) -> Self {
        self.double()
    }
}

impl Add for G2Projective {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        self.add_impl(&rhs)
    }
}

impl Add<&Self> for G2Projective {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self {
        self.add_impl(rhs)
    }
}

impl Add<&G2Projective> for &G2Projective {
    type Output = G2Projective;

    #[inline]
    fn add(self, rhs: &G2Projective) -> G2Projective {
        self.add_impl(rhs)
    }
}

impl AddAssign for G2Projective {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add_impl(&rhs);
    }
}

impl AddAssign<&Self> for G2Projective {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        *self = self.add_impl(rhs);
    }
}

impl Sub for G2Projective {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        self.sub_impl(&rhs)
    }
}

impl Sub<&Self> for G2Projective {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &Self) -> Self {
        self.sub_impl(rhs)
    }
}

impl Sub<&G2Projective> for &G2Projective {
    type Output = G2Projective;

    #[inline]
    fn sub(self, rhs: &G2Projective) -> G2Projective {
        self.sub_impl(rhs)
    }
}

impl SubAssign for G2Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub_impl(&rhs);
    }
}

impl SubAssign<&Self> for G2Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        *self = self.sub_impl(rhs);
    }
}

impl Neg for G2Projective {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        self.neg_impl()
    }
}

impl Neg for &G2Projective {
    type Output = G2Projective;

    #[inline]
    fn neg(self) -> G2Projective {
        self.neg_impl()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{Fp, scalar::tests::arb_scalar};

    /// Random G2 points, as random multiples of the generator.
    pub(crate) fn arb_g2() -> impl Strategy<Value = G2Projective> {
        arb_scalar().prop_map(|scalar| G2Projective::GENERATOR * scalar)
    }

    /// Random points of the whole twist E'(F_{p^2}), mostly outside G2.
    fn arb_twist_point() -> impl Strategy<Value = G2Affine> {
        any::<[u8; 64]>().prop_filter_map("x must complete to a curve point", |bytes| {
            // Draw x and keep it when x^3 + b' is a square.
            let x = Fp2::new(Fp::from_bytes_wide_be(&bytes), Fp::ONE);
            let y = (x.square() * x + B).sqrt()?;
            Some(G2Affine {
                x,
                y,
                infinity: false,
            })
        })
    }

    /// Multiplies by an integer given as limbs, outside the scalar field.
    fn mul_by_limbs(point: &G2Projective, limbs: &[u64]) -> G2Projective {
        // Left-to-right double-and-add over every bit, leading zeros included.
        let mut result = G2Projective::IDENTITY;
        for limb in limbs.iter().rev() {
            for bit in (0..64).rev() {
                result = result.double();
                if (limb >> bit) & 1 == 1 {
                    result += point;
                }
            }
        }
        result
    }

    /// The group order r.
    const ORDER: [u64; 4] = [
        0xffff_ffff_0000_0001,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ];

    /// The effective cofactor h_eff of RFC 9380 section 8.8.2, little-endian limbs.
    const H_EFF: [u64; 10] = [
        0xe802_0005_aaa9_5551,
        0x5989_4c0a_debb_f6b4,
        0xe954_cbc0_6689_f6a3,
        0x2ec0_ec69_d747_7c1a,
        0x6d82_bf01_5d12_12b0,
        0x329c_2f17_8731_db95,
        0x9986_ff03_1508_ffe1,
        0x88e2_a8e9_145a_d768,
        0x584c_6a0e_a91b_3528,
        0x0bc6_9f08_f2ee_75b3,
    ];

    #[test]
    fn generator_has_order_r() {
        assert!(mul_by_limbs(&G2Projective::GENERATOR, &ORDER).is_identity());
    }

    #[test]
    fn psi_acts_as_multiplication_by_x_on_the_generator() {
        // p = x mod r, so on G2 the Frobenius-like endomorphism is the scalar x.
        let g = G2Projective::GENERATOR;
        assert_eq!(g.psi(), g.mul_by_x());
        assert_eq!(g.psi().psi(), g.psi2());
    }

    proptest! {
        #[test]
        fn group_laws_hold(a in arb_g2(), b in arb_g2(), c in arb_g2()) {
            // Associativity, commutativity, and doubling as self-addition.
            prop_assert_eq!((a + b) + c, a + (b + c));
            prop_assert_eq!(a + b, b + a);
            prop_assert_eq!(a.double(), a + a);
            // Sums stay on the curve, and every point has an inverse.
            prop_assert!((a + b).is_on_curve());
            prop_assert!((a - a).is_identity());
            prop_assert_eq!(a + G2Affine::from(b), a + b);
        }

        #[test]
        fn scalar_multiplication_is_linear(a in arb_g2(), k in arb_scalar(), l in arb_scalar()) {
            prop_assert_eq!(a * (k + l), a * k + a * l);
            prop_assert_eq!(a.mul_vartime(&k), a * k);
        }

        #[test]
        fn psi_squared_shortcut_matches_twice_psi(point in arb_twist_point()) {
            let point = G2Projective::from(point);
            prop_assert_eq!(point.psi().psi(), point.psi2());
        }

        #[test]
        fn cofactor_clearing_matches_h_eff(point in arb_twist_point()) {
            // The psi polynomial equals the scalar h_eff on the whole twist, not only on G2.
            let point = G2Projective::from(point);
            let cleared = point.clear_cofactor();
            prop_assert_eq!(cleared, mul_by_limbs(&point, &H_EFF));
            prop_assert!(G2Affine::from(cleared).is_torsion_free());
        }

        #[test]
        fn fast_subgroup_check_matches_order_check(point in arb_twist_point()) {
            let order_check = mul_by_limbs(&G2Projective::from(point), &ORDER).is_identity();
            prop_assert_eq!(point.is_torsion_free(), order_check);
        }

        #[test]
        fn multi_exp_matches_naive_sum(
            terms in proptest::collection::vec((arb_g2(), arb_scalar()), 0..24)
        ) {
            // Reference: one constant-time multiplication per term, then a plain sum.
            let points: Vec<G2Affine> = terms.iter().map(|(p, _)| G2Affine::from(p)).collect();
            let scalars: Vec<Scalar> = terms.iter().map(|(_, k)| *k).collect();
            let expected: G2Projective = terms.iter().map(|(p, k)| *p * k).sum();
            prop_assert_eq!(G2Projective::multi_exp(&points, &scalars), expected);
        }

        #[test]
        fn encodings_round_trip(a in arb_g2()) {
            let affine = G2Affine::from(a);
            prop_assert_eq!(G2Affine::from_compressed(&affine.to_compressed()), Ok(affine));
            prop_assert_eq!(G2Affine::from_uncompressed(&affine.to_uncompressed()), Ok(affine));
        }
    }
}
