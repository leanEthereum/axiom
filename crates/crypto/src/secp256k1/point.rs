//! Points of the curve y^2 = x^3 + 7 over GF(p), in affine and Jacobian coordinates.

use super::{field::FieldElement, scalar::Scalar};
use crate::ct::Mask;

/// SEC 1 prefix of a compressed point with even y, per section 2.3.3.
const TAG_EVEN: u8 = 0x02;

/// SEC 1 prefix of a compressed point with odd y.
const TAG_ODD: u8 = 0x03;

/// SEC 1 prefix of an uncompressed point.
const TAG_UNCOMPRESSED: u8 = 0x04;

/// A finite curve point in affine coordinates.
///
/// # Invariants
///
/// The point satisfies y^2 = x^3 + 7, and is never the point at infinity.
/// Since secp256k1 has cofactor 1, every such point has prime order n.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct AffinePoint {
    /// The x-coordinate.
    pub(super) x: FieldElement,
    /// The y-coordinate.
    pub(super) y: FieldElement,
}

impl AffinePoint {
    /// The generator G, per SEC 2, section 2.4.1.
    pub(super) const GENERATOR: Self = Self {
        x: FieldElement::from_limbs([
            0x59f2_815b_16f8_1798,
            0x029b_fcdb_2dce_28d9,
            0x55a0_6295_ce87_0b07,
            0x79be_667e_f9dc_bbac,
        ]),
        y: FieldElement::from_limbs([
            0x9c47_d08f_fb10_d4b8,
            0xfd17_b448_a685_5419,
            0x5da4_fbfc_0e11_08a8,
            0x483a_da77_26a3_c465,
        ]),
    };

    /// The point with the given coordinates, if it lies on the curve.
    pub(super) fn new(x: FieldElement, y: FieldElement) -> Option<Self> {
        // Check y^2 = x^3 + 7.
        let on_curve = y.square().equals(Self::curve_rhs(x));
        on_curve.reveal().then_some(Self { x, y })
    }

    /// The point with the given x-coordinate and y parity, if x is on the curve.
    ///
    /// This is point decompression, per SEC 1, section 2.3.4.
    pub(super) fn decompress(x: FieldElement, y_is_odd: bool) -> Option<Self> {
        // y^2 = x^3 + 7 has a root exactly when x is the abscissa of a point.
        let y = Self::curve_rhs(x).sqrt()?;

        // The two roots y and p - y have opposite parity.
        // Pick the requested one.
        let flip = Mask::from_bit(y.is_odd().bit() ^ u64::from(y_is_odd));
        Some(Self {
            x,
            y: FieldElement::select(flip, y.neg(), y),
        })
    }

    /// Decodes the 33-byte SEC 1 compressed form, prefix 0x02 or 0x03 then x.
    ///
    /// Refuses a wrong prefix, x not below p, or x with no point on the curve.
    pub(super) fn from_compressed(bytes: &[u8; 33]) -> Option<Self> {
        // The prefix byte carries the parity of y.
        let (&tag, x) = bytes.split_first_chunk::<1>()?;
        let y_is_odd = match tag {
            [TAG_EVEN] => false,
            [TAG_ODD] => true,
            _ => return None,
        };
        let x = FieldElement::from_bytes(x.try_into().ok()?)?;
        Self::decompress(x, y_is_odd)
    }

    /// Decodes the 65-byte SEC 1 uncompressed form, prefix 0x04 then x then y.
    ///
    /// Refuses a wrong prefix, a coordinate not below p, or a point off the curve.
    pub(super) fn from_uncompressed(bytes: &[u8; 65]) -> Option<Self> {
        // Only the plain uncompressed prefix is accepted.
        let ([TAG_UNCOMPRESSED], coordinates) = bytes.split_first_chunk::<1>()? else {
            return None;
        };
        let (coordinates, _) = coordinates.as_chunks::<32>();
        let x = FieldElement::from_bytes(&coordinates[0])?;
        let y = FieldElement::from_bytes(&coordinates[1])?;
        Self::new(x, y)
    }

    /// The 33-byte SEC 1 compressed form, per section 2.3.3.
    pub(super) fn to_compressed(self) -> [u8; 33] {
        // Prefix 0x02 or 0x03 by parity of y, then x big-endian.
        let mut out = [0_u8; 33];
        // Timing: the parity bit is added, not branched on, since a shared point is secret.
        out[0] = TAG_EVEN + self.y.is_odd().bit() as u8;
        out[1..].copy_from_slice(&self.x.to_bytes());
        out
    }

    /// The 65-byte SEC 1 uncompressed form.
    pub(super) fn to_uncompressed(self) -> [u8; 65] {
        // Prefix 0x04, then x and y big-endian.
        let mut out = [0_u8; 65];
        out[0] = TAG_UNCOMPRESSED;
        out[1..33].copy_from_slice(&self.x.to_bytes());
        out[33..].copy_from_slice(&self.y.to_bytes());
        out
    }

    /// The right-hand side x^3 + 7.
    fn curve_rhs(x: FieldElement) -> FieldElement {
        // x^3 + 7, the right-hand side of the curve equation.
        x.square().mul(x).add(FieldElement::B)
    }

    /// The negated point (x, -y).
    #[cfg(test)]
    #[must_use]
    pub(super) fn neg(self) -> Self {
        Self {
            x: self.x,
            y: self.y.neg(),
        }
    }

    /// The same point with Z = 1.
    pub(super) const fn to_jacobian(self) -> JacobianPoint {
        JacobianPoint {
            x: self.x,
            y: self.y,
            z: FieldElement::ONE,
        }
    }

    /// The first point when the condition holds, the second otherwise.
    pub(super) fn select(condition: Mask, if_true: Self, if_false: Self) -> Self {
        Self {
            x: FieldElement::select(condition, if_true.x, if_false.x),
            y: FieldElement::select(condition, if_true.y, if_false.y),
        }
    }
}

/// A curve point in Jacobian coordinates, the point at infinity included.
///
/// # Overview
///
/// (X : Y : Z) stands for the affine point (X / Z^2, Y / Z^3).
/// Z = 0 stands for the point at infinity.
///
/// Additions and doublings then need no field inversion.
/// One inversion at the end converts back.
#[derive(Clone, Copy, Debug)]
pub(super) struct JacobianPoint {
    /// The X coordinate.
    pub(super) x: FieldElement,
    /// The Y coordinate.
    pub(super) y: FieldElement,
    /// The Z coordinate, zero at infinity.
    pub(super) z: FieldElement,
}

impl JacobianPoint {
    /// The point at infinity, the group identity.
    pub(super) const IDENTITY: Self = Self {
        x: FieldElement::ONE,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    /// Holds at the point at infinity.
    pub(super) fn is_identity(&self) -> Mask {
        // Z = 0 encodes the point at infinity.
        self.z.is_zero()
    }

    /// The first point when the condition holds, the second otherwise.
    pub(super) fn select(condition: Mask, if_true: &Self, if_false: &Self) -> Self {
        Self {
            x: FieldElement::select(condition, if_true.x, if_false.x),
            y: FieldElement::select(condition, if_true.y, if_false.y),
            z: FieldElement::select(condition, if_true.z, if_false.z),
        }
    }

    /// The affine form, or nothing at infinity.
    ///
    /// The inversion runs in constant time.
    /// Only whether the point is at infinity is revealed.
    pub(super) fn to_affine(self) -> Option<AffinePoint> {
        if self.is_identity().reveal() {
            return None;
        }
        // x = X / Z^2, y = Y / Z^3.
        let z_inv = self.z.invert();
        let z_inv2 = z_inv.square();
        Some(AffinePoint {
            x: self.x.mul(z_inv2),
            y: self.y.mul(z_inv2).mul(z_inv),
        })
    }

    /// The negated point (X : -Y : Z).
    #[must_use]
    pub(super) fn neg(&self) -> Self {
        Self {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Twice the point.
    ///
    /// Formula dbl-2009-l for a = 0, from the Explicit-Formulas Database.
    /// The identity maps to itself, since Z3 = 2 Y Z = 0.
    /// No point of secp256k1 has Y = 0, so no other input is exceptional.
    #[must_use]
    #[expect(
        clippy::many_single_char_names,
        reason = "the names follow the formula database"
    )]
    pub(super) fn double(&self) -> Self {
        // A = X^2, B = Y^2, C = B^2.
        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();

        // D = 2 ((X + B)^2 - A - C) = 4 X Y^2.
        let d = self.x.add(b).square().sub(a).sub(c).double();

        // E = 3 X^2 is the tangent slope numerator, F = E^2.
        let e = a.double().add(a);
        let f = e.square();

        // X3 = F - 2D, Y3 = E (D - X3) - 8C, Z3 = 2 Y Z.
        let x3 = f.sub(d.double());
        let eight_c = c.double().double().double();
        let y3 = e.mul(d.sub(x3)).sub(eight_c);
        let z3 = self.y.mul(self.z).double();
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// The sum with an affine point, when the inputs are not exceptional.
    ///
    /// Formula madd-1998-cmo with Z2 = 1.
    ///
    /// # Exceptions
    ///
    /// The result is meaningless when this point is the identity or equals the other.
    /// When it is the negation, the result is correctly the identity, since H = 0.
    /// Callers prove the exceptions cannot occur, or blend them away with selections.
    #[must_use]
    pub(super) fn add_affine_unchecked(&self, other: &AffinePoint) -> Self {
        // Bring the affine point to this point's denominator: U2 = X2 Z1^2, S2 = Y2 Z1^3.
        let z1z1 = self.z.square();
        let u2 = other.x.mul(z1z1);
        let s2 = other.y.mul(self.z).mul(z1z1);

        // H and R are the x and y differences, scaled.
        // H = 0 means equal x.
        let h = u2.sub(self.x);
        let r = s2.sub(self.y);
        Self::finish_add(self.x, self.y, h, r, self.z.mul(h))
    }

    /// The sum with another Jacobian point, when the inputs are not exceptional.
    ///
    /// Formula add-1998-cmo-2.
    ///
    /// # Exceptions
    ///
    /// The result is meaningless when either input is the identity or the two are equal.
    #[must_use]
    pub(super) fn add_unchecked(&self, other: &Self) -> Self {
        // Both points move to the common denominator Z1^2 Z2^2.
        let (h, r, u1, s1) = self.differences(other);
        Self::finish_add(u1, s1, h, r, self.z.mul(other.z).mul(h))
    }

    /// The sum, for every pair of inputs, in constant time.
    ///
    /// Tests use it as the complete group law.
    ///
    /// The generic sum, the doubling, and both identity cases are all computed.
    /// Masks then pick the right one, so the inputs never steer a branch.
    #[cfg(test)]
    #[must_use]
    pub(super) fn add(&self, other: &Self) -> Self {
        // Compute every candidate result, then choose by masks.
        let (h, r, _, _) = self.differences(other);
        let sum = self.add_unchecked(other);
        let doubled = self.double();

        // Equal inputs: H = 0 and R = 0, so take the doubling.
        let same = h.is_zero().and(r.is_zero());
        let result = Self::select(same, &doubled, &sum);

        // An identity input: the sum is the other input.
        let result = Self::select(self.is_identity(), other, &result);
        Self::select(other.is_identity(), self, &result)
    }

    /// The sum, for every pair of inputs, branching on public structure.
    ///
    /// Used only on public points, such as during verification.
    #[must_use]
    pub(super) fn add_vartime(&self, other: &Self) -> Self {
        // Identity inputs return the other point.
        if self.is_identity().reveal() {
            return *other;
        }
        if other.is_identity().reveal() {
            return *self;
        }
        let (h, r, _, _) = self.differences(other);
        if h.is_zero().reveal() {
            // Same x: either the same point, or opposite points summing to the identity.
            return if r.is_zero().reveal() {
                self.double()
            } else {
                Self::IDENTITY
            };
        }
        self.add_unchecked(other)
    }

    /// The sum with an affine point, for every input, branching on public structure.
    #[must_use]
    pub(super) fn add_affine_vartime(&self, other: &AffinePoint) -> Self {
        // Z = 1 lifts the affine point.
        // The general addition handles every case.
        self.add_vartime(&other.to_jacobian())
    }

    /// The scaled differences H, R and the scaled first point U1, S1 of two points.
    ///
    /// ```text
    /// U1 = X1 Z2^2   U2 = X2 Z1^2   H = U2 - U1
    /// S1 = Y1 Z2^3   S2 = Y2 Z1^3   R = S2 - S1
    /// ```
    fn differences(
        &self,
        other: &Self,
    ) -> (FieldElement, FieldElement, FieldElement, FieldElement) {
        // Scale both points to the common denominator Z1^2 Z2^2 (for x) and Z1^3 Z2^3 (for y).
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x.mul(z2z2);
        let u2 = other.x.mul(z1z1);
        let s1 = self.y.mul(other.z).mul(z2z2);
        let s2 = other.y.mul(self.z).mul(z1z1);
        (u2.sub(u1), s2.sub(s1), u1, s1)
    }

    /// The shared tail of both additions.
    ///
    /// ```text
    /// X3 = R^2 - H^3 - 2 U1 H^2
    /// Y3 = R (U1 H^2 - X3) - S1 H^3
    /// ```
    fn finish_add(
        u1: FieldElement,
        s1: FieldElement,
        h: FieldElement,
        r: FieldElement,
        z3: FieldElement,
    ) -> Self {
        // H^2 and H^3 recur in both coordinates.
        let hh = h.square();
        let hhh = hh.mul(h);
        let v = u1.mul(hh);
        let x3 = r.square().sub(hhh).sub(v.double());
        let y3 = r.mul(v.sub(x3)).sub(s1.mul(hhh));
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Holds when the two points are the same group element.
    #[cfg(test)]
    pub(super) fn equals(&self, other: &Self) -> Mask {
        // Compare cross-multiplied coordinates, so different Z scalings agree.
        let (h, r, _, _) = self.differences(other);
        let both_finite_and_equal = h
            .is_zero()
            .and(r.is_zero())
            .and(self.is_identity().not())
            .and(other.is_identity().not());
        let both_identity = self.is_identity().and(other.is_identity());
        both_finite_and_equal.or(both_identity)
    }

    /// The point times a secret scalar, in constant time.
    ///
    /// # Algorithm
    ///
    /// Fixed 4-bit windows from the top, with a table of the first 15 multiples.
    ///
    /// ```text
    /// acc = 0
    /// for each digit d of k, high to low:
    ///     acc = 16 acc            four doublings
    ///     acc = acc + d P         table entry read by a full scan
    /// ```
    ///
    /// # Exceptions
    ///
    /// The unchecked addition never sees equal or opposite inputs.
    /// Before window i, acc = A P with A = 16 floor(k / 16^(i + 1)), a multiple of 16.
    ///
    /// - A = d is impossible for 1 <= d <= 15 unless acc is the identity.
    /// - A + d = floor(k / 16^i) <= k < n, so A = -d mod n is impossible.
    ///
    /// The two remaining cases, a zero digit and an identity accumulator, are blended by masks.
    pub(super) fn mul_ct(&self, k: &Scalar) -> Self {
        // Phase 1: table[j - 1] = j P for j = 1..15.
        //
        // j P + P is exceptional only for j = 1 or j = n - 1, so 2P takes a doubling.
        let mut table = [*self; 15];
        table[1] = self.double();
        for j in 2..15 {
            table[j] = table[j - 1].add_unchecked(self);
        }

        // Phase 2: 64 windows, high to low.
        let mut acc = Self::IDENTITY;
        for window in (0..64).rev() {
            acc = acc.double().double().double().double();
            let digit = k.nibble(window);

            // Read d P by touching every entry, so the digit picks no address.
            let mut entry = table[0];
            for (j, candidate) in (1..).zip(&table) {
                entry = Self::select(Mask::equal(digit, j), candidate, &entry);
            }

            // Blend the exceptional cases away.
            //
            //     acc = 0, d != 0  -> d P
            //     d = 0            -> acc unchanged
            let sum = acc.add_unchecked(&entry);
            let sum = Self::select(acc.is_identity(), &entry, &sum);
            acc = Self::select(Mask::is_zero(digit), &acc, &sum);
        }
        acc
    }

    /// The point times a public scalar, by width-5 NAF.
    ///
    /// Used only on public inputs: the digit pattern steers branches and table indices.
    pub(super) fn mul_vartime(&self, k: &Scalar) -> Self {
        // Odd multiples P, 3P, ..., 15P cover every width-5 digit magnitude.
        let doubled = self.double();
        let mut odd = [*self; 8];
        for j in 1..8 {
            odd[j] = odd[j - 1].add_vartime(&doubled);
        }

        // Scan the digits high to low: double, then add or subtract a table entry.
        let digits = k.wnaf_vartime(5);
        let mut acc = Self::IDENTITY;
        for &digit in digits.iter().rev() {
            acc = acc.double();
            if digit > 0 {
                acc = acc.add_vartime(&odd[usize::from(digit.unsigned_abs()) / 2]);
            } else if digit < 0 {
                acc = acc.add_vartime(&odd[usize::from(digit.unsigned_abs()) / 2].neg());
            }
        }
        acc
    }
}

#[cfg(test)]
pub(super) mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::secp256k1::scalar::tests::arb_scalar;

    /// The point times a scalar by double-and-add, the textbook reference.
    pub(crate) fn mul_reference(point: &JacobianPoint, k: &Scalar) -> JacobianPoint {
        // Scan k from the top bit: double, then add the point on a set bit.
        let mut acc = JacobianPoint::IDENTITY;
        for bit in (0..256).rev() {
            acc = acc.add_vartime(&acc);
            if k.bit(bit) == 1 {
                acc = acc.add_vartime(point);
            }
        }
        acc
    }

    /// A random point: a random multiple of the generator.
    pub(crate) fn arb_point() -> impl Strategy<Value = JacobianPoint> {
        // k G for a random k covers the whole group, identity included.
        arb_scalar().prop_map(|k| AffinePoint::GENERATOR.to_jacobian().mul_vartime(&k))
    }

    /// Asserts two points are the same group element.
    fn assert_same(a: &JacobianPoint, b: &JacobianPoint) {
        // Compare as group elements, whatever the Z scaling.
        assert!(a.equals(b).reveal(), "{a:?} != {b:?}");
    }

    #[test]
    fn generator_lies_on_the_curve() {
        // G passes the curve equation check.
        let g = AffinePoint::GENERATOR;
        assert_eq!(AffinePoint::new(g.x, g.y), Some(g));

        // n G = 0: the order is n.
        let order_minus_one = Scalar::ONE.neg();
        let almost = mul_reference(&g.to_jacobian(), &order_minus_one);
        assert!(almost.add_vartime(&g.to_jacobian()).is_identity().reveal());
    }

    #[test]
    fn decompression_picks_the_requested_parity() {
        // Both parities of G's x give G and -G.
        let g = AffinePoint::GENERATOR;
        let even = AffinePoint::decompress(g.x, false).unwrap();
        let odd = AffinePoint::decompress(g.x, true).unwrap();
        assert_eq!(even, g);
        assert_eq!(odd, g.neg());

        // x = 0 gives y^2 = 7, a non-residue: no point.
        assert_eq!(AffinePoint::decompress(FieldElement::ZERO, false), None);
    }

    #[test]
    fn edge_scalars() {
        // 0, 1, 2, n - 1 and n - 2 through all three multipliers.
        let g = AffinePoint::GENERATOR.to_jacobian();
        let scalars = [
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::ONE.add(Scalar::ONE),
            Scalar::ONE.neg(),
            Scalar::ONE.add(Scalar::ONE).neg(),
        ];
        for k in scalars {
            let reference = mul_reference(&g, &k);
            assert_same(&g.mul_ct(&k), &reference);
            assert_same(&g.mul_vartime(&k), &reference);
        }

        // (n - 1) G = -G.
        assert_same(&g.mul_ct(&Scalar::ONE.neg()), &g.neg());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn constant_time_ladder_matches_double_and_add(p in arb_point(), k in arb_scalar()) {
            // Fixed windows with masked exceptions equal the textbook method.
            prop_assert!(p.mul_ct(&k).equals(&mul_reference(&p, &k)).reveal());
        }

        #[test]
        fn wnaf_matches_double_and_add(p in arb_point(), k in arb_scalar()) {
            // The variable-time NAF method equals the textbook method.
            prop_assert!(p.mul_vartime(&k).equals(&mul_reference(&p, &k)).reveal());
        }

        #[test]
        fn group_laws(a in arb_point(), b in arb_point(), c in arb_point()) {
            let zero = JacobianPoint::IDENTITY;

            // Identity, inverse, commutativity, associativity.
            prop_assert!(a.add(&zero).equals(&a).reveal());
            prop_assert!(a.add(&a.neg()).is_identity().reveal());
            prop_assert!(a.add(&b).equals(&b.add(&a)).reveal());
            prop_assert!(a.add(&b).add(&c).equals(&a.add(&b.add(&c))).reveal());

            // The complete addition doubles equal inputs.
            prop_assert!(a.add(&a).equals(&a.double()).reveal());

            // The constant-time and branching additions agree.
            prop_assert!(a.add(&b).equals(&a.add_vartime(&b)).reveal());
        }

        #[test]
        fn scalar_multiplication_is_a_homomorphism(a in arb_scalar(), b in arb_scalar()) {
            // (a + b) G = a G + b G and (a b) G = a (b G).
            let g = AffinePoint::GENERATOR.to_jacobian();
            let sum = g.mul_ct(&a.add(b));
            prop_assert!(sum.equals(&g.mul_ct(&a).add(&g.mul_ct(&b))).reveal());
            let product = g.mul_ct(&a.mul(b));
            prop_assert!(product.equals(&g.mul_ct(&b).mul_ct(&a)).reveal());
        }

        #[test]
        fn affine_round_trip(p in arb_point()) {
            // Affine conversion lands on the curve and represents the same point.
            if let Some(affine) = p.to_affine() {
                prop_assert_eq!(AffinePoint::new(affine.x, affine.y), Some(affine));
                prop_assert!(affine.to_jacobian().equals(&p).reveal());
            }
        }
    }
}
