//! G1 points in homogeneous projective coordinates, with complete addition formulas.
//!
//! A point (X : Y : Z) stands for the affine point (X / Z, Y / Z); Z = 0 is the point at infinity.
//! The formulas are those of Renes, Costello, and Batina, "Complete addition formulas for prime order elliptic curves", eprint 2015/1060, specialized to a = 0.
//! Complete means one formula handles every input, including doubling and the identity.
//! There is no branch to leak timing, and no exceptional case to forget.

use std::{
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use super::{B, B3, G1Affine};
use crate::{
    BLS_X, Fp, Scalar,
    msm::{self, PippengerGroup},
};

/// A point of E(F_p) in homogeneous projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct G1Projective {
    /// The X coordinate.
    pub(crate) x: Fp,
    /// The Y coordinate.
    pub(crate) y: Fp,
    /// The Z coordinate, zero exactly at infinity.
    pub(crate) z: Fp,
}

impl G1Projective {
    /// The point at infinity (0 : 1 : 0).
    pub const IDENTITY: Self = Self {
        x: Fp::ZERO,
        y: Fp::ONE,
        z: Fp::ZERO,
    };

    /// The standard generator of G1.
    pub const GENERATOR: Self = Self {
        x: G1Affine::GENERATOR.x,
        y: G1Affine::GENERATOR.y,
        z: Fp::ONE,
    };

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
        let t0 = self.y.square();
        let z3 = t0.double().double().double();
        let t1 = self.y * self.z;
        let t2 = self.z.square() * B3;
        let x3 = t2 * z3;
        let y3 = t0 + t2;
        let z3 = t1 * z3;
        let t1 = t2.double();
        let t2 = t1 + t2;
        let t0 = t0 - t2;
        let y3 = t0 * y3 + x3;
        let t1 = self.x * self.y;
        let x3 = (t0 * t1).double();
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
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

    /// Computes sum_i scalars[i] * points[i] with Pippenger's bucket method.
    ///
    /// The running time depends on the scalars, which must be public.
    ///
    /// # Panics
    ///
    /// Panics when the two slices differ in length.
    #[must_use]
    pub fn multi_exp(points: &[G1Affine], scalars: &[Scalar]) -> Self {
        msm::multi_exp(points, scalars)
    }

    /// Converts many points to affine form with a single field inversion.
    #[must_use]
    pub fn batch_normalize(points: &[Self]) -> Vec<G1Affine> {
        // Phase 1: running products of the nonzero Z coordinates.
        let mut prefixes = Vec::with_capacity(points.len());
        let mut product = Fp::ONE;
        for point in points {
            prefixes.push(product);
            if !point.is_identity() {
                product *= point.z;
            }
        }

        // Phase 2: one inversion of the total product, nonzero by construction.
        let mut inverse = product.invert().unwrap_or(Fp::ZERO);

        // Phase 3: walk back, reading off each 1 / Z and peeling it from the inverse.
        let mut affine = vec![G1Affine::IDENTITY; points.len()];
        for ((out, point), prefix) in affine.iter_mut().zip(points).zip(prefixes).rev() {
            if point.is_identity() {
                continue;
            }
            let z_inverse = inverse * prefix;
            inverse *= point.z;
            *out = G1Affine {
                x: point.x * z_inverse,
                y: point.y * z_inverse,
                infinity: false,
            };
        }
        affine
    }

    /// Picks the second point when the flag is set, the first otherwise, without branching.
    pub(crate) fn conditional_select(a: &Self, b: &Self, choice: bool) -> Self {
        Self {
            x: Fp::conditional_select(&a.x, &b.x, choice),
            y: Fp::conditional_select(&a.y, &b.y, choice),
            z: Fp::conditional_select(&a.z, &b.z, choice),
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
        let t0 = self.x * rhs.x;
        let t1 = self.y * rhs.y;
        let t2 = self.z * rhs.z;
        let t3 = (self.x + self.y) * (rhs.x + rhs.y) - (t0 + t1);
        let t4 = (self.y + self.z) * (rhs.y + rhs.z) - (t1 + t2);
        let y3 = (self.x + self.z) * (rhs.x + rhs.z) - (t0 + t2);
        let t0 = t0.double() + t0;
        let t2 = t2 * B3;
        let z3 = t1 + t2;
        let t1 = t1 - t2;
        let y3 = y3 * B3;
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
    fn add_mixed_impl(&self, rhs: &G1Affine) -> Self {
        let t0 = self.x * rhs.x;
        let t1 = self.y * rhs.y;
        let t3 = (rhs.x + rhs.y) * (self.x + self.y) - (t0 + t1);
        let t4 = rhs.y * self.z + self.y;
        let y3 = rhs.x * self.z + self.x;
        let t0 = t0.double() + t0;
        let t2 = self.z * B3;
        let z3 = t1 + t2;
        let t1 = t1 - t2;
        let y3 = y3 * B3;
        let x3 = t3 * t1 - t4 * y3;
        let y3 = t1 * z3 + y3 * t0;
        let z3 = z3 * t4 + t0 * t3;
        let sum = Self {
            x: x3,
            y: y3,
            z: z3,
        };
        Self::conditional_select(&sum, self, rhs.infinity)
    }

    /// Returns self - rhs.
    fn sub_impl(&self, rhs: &Self) -> Self {
        self.add_impl(&rhs.neg_impl())
    }

    /// Returns -self.
    fn neg_impl(&self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }
}

impl Default for G1Projective {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl PartialEq for G1Projective {
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

impl Eq for G1Projective {}

impl From<&G1Affine> for G1Projective {
    fn from(point: &G1Affine) -> Self {
        // (x, y) lifts to (x : y : 1); infinity lifts to (0 : 1 : 0).
        Self {
            x: point.x,
            y: point.y,
            z: Fp::conditional_select(&Fp::ONE, &Fp::ZERO, point.infinity),
        }
    }
}

impl From<G1Affine> for G1Projective {
    fn from(point: G1Affine) -> Self {
        Self::from(&point)
    }
}

impl Add<&G1Affine> for G1Projective {
    type Output = Self;

    fn add(self, rhs: &G1Affine) -> Self {
        self.add_mixed_impl(rhs)
    }
}

impl Add<G1Affine> for G1Projective {
    type Output = Self;

    fn add(self, rhs: G1Affine) -> Self {
        self.add_mixed_impl(&rhs)
    }
}

impl AddAssign<&G1Affine> for G1Projective {
    fn add_assign(&mut self, rhs: &G1Affine) {
        *self = self.add_mixed_impl(rhs);
    }
}

impl AddAssign<G1Affine> for G1Projective {
    fn add_assign(&mut self, rhs: G1Affine) {
        *self = self.add_mixed_impl(&rhs);
    }
}

impl Mul<&Scalar> for &G1Projective {
    type Output = G1Projective;

    fn mul(self, scalar: &Scalar) -> G1Projective {
        self.multiply(scalar)
    }
}

impl Mul<&Scalar> for G1Projective {
    type Output = Self;

    fn mul(self, scalar: &Scalar) -> Self {
        self.multiply(scalar)
    }
}

impl Mul<Scalar> for G1Projective {
    type Output = Self;

    fn mul(self, scalar: Scalar) -> Self {
        self.multiply(&scalar)
    }
}

impl MulAssign<&Scalar> for G1Projective {
    fn mul_assign(&mut self, scalar: &Scalar) {
        *self = self.multiply(scalar);
    }
}

impl MulAssign<Scalar> for G1Projective {
    fn mul_assign(&mut self, scalar: Scalar) {
        *self = self.multiply(&scalar);
    }
}

impl Sum for G1Projective {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::IDENTITY, |acc, point| acc + point)
    }
}

impl<'a> Sum<&'a Self> for G1Projective {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::IDENTITY, |acc, point| acc + point)
    }
}

impl PippengerGroup for G1Projective {
    type Affine = G1Affine;

    const NEUTRAL: Self = Self::IDENTITY;

    fn double_point(&self) -> Self {
        self.double()
    }
}

impl Add for G1Projective {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        self.add_impl(&rhs)
    }
}

impl Add<&Self> for G1Projective {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self {
        self.add_impl(rhs)
    }
}

impl Add<&G1Projective> for &G1Projective {
    type Output = G1Projective;

    #[inline]
    fn add(self, rhs: &G1Projective) -> G1Projective {
        self.add_impl(rhs)
    }
}

impl AddAssign for G1Projective {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add_impl(&rhs);
    }
}

impl AddAssign<&Self> for G1Projective {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        *self = self.add_impl(rhs);
    }
}

impl Sub for G1Projective {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        self.sub_impl(&rhs)
    }
}

impl Sub<&Self> for G1Projective {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &Self) -> Self {
        self.sub_impl(rhs)
    }
}

impl Sub<&G1Projective> for &G1Projective {
    type Output = G1Projective;

    #[inline]
    fn sub(self, rhs: &G1Projective) -> G1Projective {
        self.sub_impl(rhs)
    }
}

impl SubAssign for G1Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub_impl(&rhs);
    }
}

impl SubAssign<&Self> for G1Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        *self = self.sub_impl(rhs);
    }
}

impl Neg for G1Projective {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        self.neg_impl()
    }
}

impl Neg for &G1Projective {
    type Output = G1Projective;

    #[inline]
    fn neg(self) -> G1Projective {
        self.neg_impl()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::scalar::tests::arb_scalar;

    /// Random G1 points, as random multiples of the generator.
    pub(crate) fn arb_g1() -> impl Strategy<Value = G1Projective> {
        arb_scalar().prop_map(|scalar| G1Projective::GENERATOR * scalar)
    }

    /// Reference scalar multiplication: right-to-left double-and-add with no windows.
    fn mul_reference(point: &G1Projective, scalar: &Scalar) -> G1Projective {
        let mut result = G1Projective::IDENTITY;
        let mut addend = *point;
        for limb in scalar.to_canonical() {
            for bit in 0..64 {
                if (limb >> bit) & 1 == 1 {
                    result += addend;
                }
                addend = addend.double();
            }
        }
        result
    }

    /// The group order r as limbs, to multiply by it without reducing it to zero first.
    const ORDER: [u64; 4] = [
        0xffff_ffff_0000_0001,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ];

    /// Multiplies by an integer given as limbs, outside the scalar field.
    fn mul_by_limbs(point: &G1Projective, limbs: &[u64]) -> G1Projective {
        let mut result = G1Projective::IDENTITY;
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

    #[test]
    fn generator_has_order_r() {
        // r * G = O, the definition of the subgroup order.
        assert!(mul_by_limbs(&G1Projective::GENERATOR, &ORDER).is_identity());
    }

    #[test]
    fn identity_is_neutral_for_every_formula() {
        let g = G1Projective::GENERATOR;
        // Full addition on either side.
        assert_eq!(g + G1Projective::IDENTITY, g);
        assert_eq!(G1Projective::IDENTITY + g, g);
        // Mixed addition of an affine identity, the case the formula needs a select for.
        assert_eq!(g + G1Affine::IDENTITY, g);
        // Doubling the identity stays at infinity.
        assert!(G1Projective::IDENTITY.double().is_identity());
        // P - P = O.
        assert!((g - g).is_identity());
    }

    #[test]
    fn multiplication_by_x_matches_the_parameter() {
        // x = -0xd201000000010000, so [x] G = -[0xd201000000010000] G.
        let expected = -mul_by_limbs(&G1Projective::GENERATOR, &[0xd201_0000_0001_0000]);
        assert_eq!(G1Projective::GENERATOR.mul_by_x(), expected);
    }

    #[test]
    fn batch_normalization_handles_identity() {
        // Fixture state: [G, O, 2G] mixes a finite point, infinity, and another finite point.
        let points = [
            G1Projective::GENERATOR,
            G1Projective::IDENTITY,
            G1Projective::GENERATOR.double(),
        ];
        let affine = G1Projective::batch_normalize(&points);
        let expected: Vec<G1Affine> = points.iter().map(G1Affine::from).collect();
        assert_eq!(affine, expected);
    }

    #[test]
    fn multi_exp_over_many_points_matches_one_multiplication() {
        // Fixture state: 600 points P_i = [i + 1] G with scalars k_i = i^3 + 7.
        // 600 points select 8-bit windows, so every bucket path runs.
        let mut points = Vec::new();
        let mut scalars = Vec::new();
        let mut point = G1Projective::GENERATOR;
        for i in 0..600 {
            points.push(G1Affine::from(point));
            scalars.push(Scalar::from_u64(i).pow_vartime(&[3]) + Scalar::from_u64(7));
            point += G1Projective::GENERATOR;
        }

        // Mutation: edge cases for the digit extraction and the mixed addition.
        //
        //     scalar 0      -> every digit is zero, the point never enters a bucket
        //     scalar r - 1  -> every window is busy, top bits included
        //     identity point -> the mixed addition must skip it
        scalars[0] = Scalar::ZERO;
        scalars[1] = -Scalar::ONE;
        points[2] = G1Affine::IDENTITY;

        // Reference: sum_i k_i P_i = [sum_i k_i * (i + 1)] G, skipping the identity term.
        let mut total = Scalar::ZERO;
        for (i, scalar) in (1_u64..).zip(&scalars) {
            if i != 3 {
                total += *scalar * Scalar::from_u64(i);
            }
        }
        assert_eq!(
            G1Projective::multi_exp(&points, &scalars),
            G1Projective::GENERATOR * total
        );
    }

    proptest! {
        #[test]
        fn group_laws_hold(a in arb_g1(), b in arb_g1(), c in arb_g1()) {
            prop_assert_eq!((a + b) + c, a + (b + c));
            prop_assert_eq!(a + b, b + a);
            prop_assert_eq!(a.double(), a + a);
            prop_assert!((a + b).is_on_curve());
            prop_assert!((a - a).is_identity());
        }

        #[test]
        fn mixed_addition_matches_full_addition(a in arb_g1(), b in arb_g1()) {
            prop_assert_eq!(a + G1Affine::from(b), a + b);
        }

        #[test]
        fn scalar_multiplication_matches_reference(a in arb_g1(), k in arb_scalar()) {
            let expected = mul_reference(&a, &k);
            prop_assert_eq!(a * k, expected);
            prop_assert_eq!(a.mul_vartime(&k), expected);
        }

        #[test]
        fn scalar_multiplication_is_linear(a in arb_g1(), k in arb_scalar(), l in arb_scalar()) {
            prop_assert_eq!(a * (k + l), a * k + a * l);
            prop_assert_eq!(a * (k * l), (a * k) * l);
        }

        #[test]
        fn fast_subgroup_check_matches_order_check(k in arb_scalar(), x in any::<[u8; 47]>()) {
            // Members of G1: multiples of the generator pass both checks.
            let member = G1Affine::from(G1Projective::GENERATOR * k);
            prop_assert!(member.is_torsion_free());

            // Arbitrary curve points: find one from a random x, then compare with r * P = O.
            let mut bytes = [0_u8; 48];
            bytes[1..].copy_from_slice(&x);
            bytes[0] = 0x80;
            if let Ok(point) = G1Affine::from_compressed_unchecked(&bytes) {
                let order_check = mul_by_limbs(&G1Projective::from(point), &ORDER).is_identity();
                prop_assert_eq!(point.is_torsion_free(), order_check);
            }
        }

        #[test]
        fn multi_exp_matches_naive_sum(
            terms in proptest::collection::vec((arb_g1(), arb_scalar()), 0..24)
        ) {
            // Reference: one constant-time multiplication per term, then a plain sum.
            let points: Vec<G1Affine> = terms.iter().map(|(p, _)| G1Affine::from(p)).collect();
            let scalars: Vec<Scalar> = terms.iter().map(|(_, k)| *k).collect();
            let expected: G1Projective = terms.iter().map(|(p, k)| *p * k).sum();
            prop_assert_eq!(G1Projective::multi_exp(&points, &scalars), expected);
        }

        #[test]
        fn encodings_round_trip(a in arb_g1()) {
            let affine = G1Affine::from(a);
            prop_assert_eq!(G1Affine::from_compressed(&affine.to_compressed()), Ok(affine));
            prop_assert_eq!(G1Affine::from_uncompressed(&affine.to_uncompressed()), Ok(affine));
        }
    }
}
