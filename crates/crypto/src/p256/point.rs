//! Points of the curve y^2 = x^3 - 3x + b over GF(p), in affine and projective coordinates.

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
/// The point satisfies y^2 = x^3 - 3x + b, and is never the point at infinity.
/// Since P-256 has cofactor 1, every such point has prime order n.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct AffinePoint {
    /// The x-coordinate.
    pub(super) x: FieldElement,
    /// The y-coordinate.
    pub(super) y: FieldElement,
}

impl AffinePoint {
    /// The generator G, per FIPS 186-4, appendix D.1.2.3.
    pub(super) const GENERATOR: Self = Self {
        x: FieldElement::from_canonical_const([
            0xf4a1_3945_d898_c296,
            0x7703_7d81_2deb_33a0,
            0xf8bc_e6e5_63a4_40f2,
            0x6b17_d1f2_e12c_4247,
        ]),
        y: FieldElement::from_canonical_const([
            0xcbb6_4068_37bf_51f5,
            0x2bce_3357_6b31_5ece,
            0x8ee7_eb4a_7c0f_9e16,
            0x4fe3_42e2_fe1a_7f9b,
        ]),
    };

    /// The point with the given coordinates, if it lies on the curve.
    pub(super) fn new(x: FieldElement, y: FieldElement) -> Option<Self> {
        let on_curve = y.square().equals(Self::curve_rhs(x));
        on_curve.reveal().then_some(Self { x, y })
    }

    /// The point with the given x-coordinate and y parity, if x is on the curve.
    ///
    /// This is point decompression, per SEC 1, section 2.3.4.
    pub(super) fn decompress(x: FieldElement, y_is_odd: bool) -> Option<Self> {
        // The right-hand side has a root exactly when x is the abscissa of a point.
        let y = Self::curve_rhs(x).sqrt()?;

        // The two roots y and p - y have opposite parity.
        // No root is zero: a point with y = 0 has order 2, and the group order is odd.
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
        let mut out = [0_u8; 33];
        out[0] = TAG_EVEN + self.y.is_odd().bit() as u8;
        out[1..].copy_from_slice(&self.x.to_bytes());
        out
    }

    /// The 65-byte SEC 1 uncompressed form.
    pub(super) fn to_uncompressed(self) -> [u8; 65] {
        let mut out = [0_u8; 65];
        out[0] = TAG_UNCOMPRESSED;
        out[1..33].copy_from_slice(&self.x.to_bytes());
        out[33..].copy_from_slice(&self.y.to_bytes());
        out
    }

    /// The right-hand side x^3 - 3x + b.
    fn curve_rhs(x: FieldElement) -> FieldElement {
        x.square().mul(x).sub(x.triple()).add(FieldElement::B)
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
    pub(super) const fn to_projective(self) -> ProjectivePoint {
        ProjectivePoint {
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

/// A curve point in homogeneous projective coordinates, the point at infinity included.
///
/// # Overview
///
/// (X : Y : Z) stands for the affine point (X / Z, Y / Z).
/// The point at infinity is (0 : 1 : 0).
///
/// The complete formulas of Renes, Costello and Batina need these coordinates.
/// They hold for every pair of inputs, so constant-time code needs no exception masks.
/// See "Complete addition formulas for prime order elliptic curves", EUROCRYPT 2016, section 3.2.
#[derive(Clone, Copy, Debug)]
pub(super) struct ProjectivePoint {
    /// The X coordinate.
    pub(super) x: FieldElement,
    /// The Y coordinate.
    pub(super) y: FieldElement,
    /// The Z coordinate, zero at infinity.
    pub(super) z: FieldElement,
}

impl ProjectivePoint {
    /// The point at infinity, the group identity.
    pub(super) const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    /// Holds at the point at infinity.
    pub(super) fn is_identity(&self) -> Mask {
        // On the curve, Z = 0 forces X = 0, the single point at infinity.
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
        // x = X / Z, y = Y / Z.
        let z_inv = self.z.invert();
        Some(AffinePoint {
            x: self.x.mul(z_inv),
            y: self.y.mul(z_inv),
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

    /// The sum, complete for every pair of inputs.
    ///
    /// Algorithm 4 of Renes, Costello and Batina 2016, for a = -3: 12 products and 2 by b.
    /// The numbered steps below follow the paper.
    #[must_use]
    pub(super) fn add(&self, other: &Self) -> Self {
        let (x1, y1, z1) = (self.x, self.y, self.z);
        let (x2, y2, z2) = (other.x, other.y, other.z);
        let b = FieldElement::B;

        // Steps 1 to 8: the products of like coordinates, and X1 Y2 + X2 Y1.
        let t0 = x1.mul(x2);
        let t1 = y1.mul(y2);
        let t2 = z1.mul(z2);
        let t3 = x1.add(y1).mul(x2.add(y2)).sub(t0.add(t1));

        // Steps 9 to 18: Y1 Z2 + Y2 Z1 and X1 Z2 + X2 Z1.
        let t4 = y1.add(z1).mul(y2.add(z2)).sub(t1.add(t2));
        let xz = x1.add(z1).mul(x2.add(z2)).sub(t0.add(t2));

        // Steps 19 to 24: 3 (XZ - b Z1 Z2), then Y1 Y2 minus and plus it.
        let u = xz.sub(b.mul(t2)).triple();
        let z3 = t1.sub(u);
        let x3 = t1.add(u);

        // Steps 25 to 34: 3 (b XZ - 3 Z1 Z2 - X1 X2) and 3 X1 X2 - 3 Z1 Z2.
        let t2 = t2.triple();
        let v = b.mul(xz).sub(t2).sub(t0).triple();
        let t0 = t0.triple().sub(t2);

        // Steps 35 to 43: the output coordinates.
        Self {
            x: t3.mul(x3).sub(t4.mul(v)),
            y: x3.mul(z3).add(t0.mul(v)),
            z: t4.mul(z3).add(t3.mul(t0)),
        }
    }

    /// The sum with an affine point, complete for every projective input.
    ///
    /// Algorithm 5 of Renes, Costello and Batina 2016, for a = -3: 11 products and 2 by b.
    /// The affine point is finite by its invariant, which is the formula's only requirement.
    #[must_use]
    pub(super) fn add_affine(&self, other: &AffinePoint) -> Self {
        let (x1, y1, z1) = (self.x, self.y, self.z);
        let (x2, y2) = (other.x, other.y);
        let b = FieldElement::B;

        // Steps 1 to 7: X1 X2, Y1 Y2, and X1 Y2 + X2 Y1.
        let t0 = x1.mul(x2);
        let t1 = y1.mul(y2);
        let t3 = x2.add(y2).mul(x1.add(y1)).sub(t0.add(t1));

        // Steps 8 to 11: Y2 Z1 + Y1 and X2 Z1 + X1.
        let t4 = y2.mul(z1).add(y1);
        let xz = x2.mul(z1).add(x1);

        // Steps 12 to 17: 3 (XZ - b Z1), then Y1 Y2 minus and plus it.
        let u = xz.sub(b.mul(z1)).triple();
        let z3 = t1.sub(u);
        let x3 = t1.add(u);

        // Steps 18 to 27: 3 (b XZ - 3 Z1 - X1 X2) and 3 X1 X2 - 3 Z1.
        let t2 = z1.triple();
        let v = b.mul(xz).sub(t2).sub(t0).triple();
        let t0 = t0.triple().sub(t2);

        // Steps 28 to 36: the output coordinates.
        Self {
            x: t3.mul(x3).sub(t4.mul(v)),
            y: x3.mul(z3).add(t0.mul(v)),
            z: t4.mul(z3).add(t3.mul(t0)),
        }
    }

    /// Twice the point, exception-free.
    ///
    /// Algorithm 6 of Renes, Costello and Batina 2016, for a = -3: 8 products, 3 squares, 2 by b.
    #[must_use]
    #[expect(
        clippy::many_single_char_names,
        reason = "the names follow the paper's coordinates"
    )]
    pub(super) fn double(&self) -> Self {
        let (x, y, z) = (self.x, self.y, self.z);
        let b = FieldElement::B;

        // Steps 1 to 7: the squares, 2 X Y, and 2 X Z.
        let t0 = x.square();
        let t1 = y.square();
        let t2 = z.square();
        let xy = x.mul(y).double();
        let xz = x.mul(z).double();

        // Steps 8 to 15: 3 (b Z^2 - 2 X Z), then Y^2 minus and plus it.
        let u = b.mul(t2).sub(xz).triple();
        let minus = t1.sub(u);
        let plus = t1.add(u);

        // Steps 16 to 25: 3 (2 b X Z - 3 Z^2 - X^2) and 3 X^2 - 3 Z^2.
        let t2 = t2.triple();
        let v = b.mul(xz).sub(t2).sub(t0).triple();
        let t0 = t0.triple().sub(t2);

        // Steps 26 to 34: the output coordinates, with 2 Y Z shared by X3 and Z3.
        let yz = y.mul(z).double();
        Self {
            x: minus.mul(xy).sub(yz.mul(v)),
            y: plus.mul(minus).add(t0.mul(v)),
            z: yz.mul(t1).double().double(),
        }
    }

    /// Holds when the two points are the same group element.
    #[cfg(test)]
    pub(super) fn equals(&self, other: &Self) -> Mask {
        // Cross-multiply, so different Z scalings agree.
        // Two points at infinity agree too, since both X are zero.
        let x = self.x.mul(other.z).equals(other.x.mul(self.z));
        let y = self.y.mul(other.z).equals(other.y.mul(self.z));
        let both_infinite = self.is_identity().and(other.is_identity());
        let one_infinite = self.is_identity().or(other.is_identity());
        x.and(y).and(one_infinite.not()).or(both_infinite)
    }

    /// The point times a secret scalar, in constant time.
    ///
    /// # Algorithm
    ///
    /// Fixed 4-bit windows, high to low, over the multiples 0 P to 15 P.
    ///
    /// ```text
    /// table[j] = j P                 for j = 0..15
    /// acc = 16 acc + table[d_i]      for each 4-bit digit d_i of k, high to low
    /// ```
    ///
    /// Every window costs four doublings, one full table scan, and one addition.
    /// The scan blends each entry under a mask, so the digit picks no address.
    /// The complete formulas take the identity and equal inputs, so no digit picks a branch.
    pub(super) fn mul_ct(&self, k: &Scalar) -> Self {
        // Phase 1: the 16 multiples, the identity first.
        let mut table = [Self::IDENTITY; 16];
        for j in 1..16 {
            table[j] = table[j - 1].add(self);
        }

        // Phase 2: 64 windows, high to low.
        let mut acc = Self::IDENTITY;
        for window in (0..64).rev() {
            acc = acc.double().double().double().double();
            let digit = k.nibble(window);

            // Read d P by touching every entry.
            let mut entry = Self::IDENTITY;
            for (j, candidate) in (0..).zip(&table) {
                entry = Self::select(Mask::equal(digit, j), candidate, &entry);
            }
            acc = acc.add(&entry);
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
            odd[j] = odd[j - 1].add(&doubled);
        }

        // Scan the digits high to low: double, then add or subtract a table entry.
        let digits = k.wnaf_vartime(5);
        let mut acc = Self::IDENTITY;
        for &digit in digits.iter().rev() {
            acc = acc.double();
            let entry = &odd[usize::from(digit.unsigned_abs()) / 2];
            if digit > 0 {
                acc = acc.add(entry);
            } else if digit < 0 {
                acc = acc.add(&entry.neg());
            }
        }
        acc
    }
}

#[cfg(test)]
pub(super) mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::p256::scalar::tests::arb_scalar;

    /// The affine group law with inversions, the textbook reference, none standing for infinity.
    fn add_reference(a: Option<AffinePoint>, b: Option<AffinePoint>) -> Option<AffinePoint> {
        let (Some(a), Some(b)) = (a, b) else {
            return a.or(b);
        };
        let slope = if a.x == b.x {
            if a.y != b.y || a.y == FieldElement::ZERO {
                // Opposite points.
                return None;
            }
            // Tangent: (3 x^2 - 3) / 2 y.
            a.x.square()
                .sub(FieldElement::ONE)
                .triple()
                .mul(a.y.double().invert())
        } else {
            // Chord: (y2 - y1) / (x2 - x1).
            b.y.sub(a.y).mul(b.x.sub(a.x).invert())
        };
        let x = slope.square().sub(a.x).sub(b.x);
        let y = slope.mul(a.x.sub(x)).sub(a.y);
        Some(AffinePoint { x, y })
    }

    /// The point times a scalar by double-and-add over the affine reference law.
    pub(crate) fn mul_reference(point: Option<AffinePoint>, k: &Scalar) -> Option<AffinePoint> {
        let mut acc = None;
        for bit in (0..256).rev() {
            acc = add_reference(acc, acc);
            if k.bit(bit) == 1 {
                acc = add_reference(acc, point);
            }
        }
        acc
    }

    /// A random point: a random multiple of the generator, infinity included.
    pub(crate) fn arb_point() -> impl Strategy<Value = ProjectivePoint> {
        arb_scalar().prop_map(|k| AffinePoint::GENERATOR.to_projective().mul_vartime(&k))
    }

    #[test]
    fn generator_lies_on_the_curve_and_has_order_n() {
        let g = AffinePoint::GENERATOR;
        assert_eq!(AffinePoint::new(g.x, g.y), Some(g));

        // (n - 1) G = -G, so n G = 0.
        assert_eq!(mul_reference(Some(g), &Scalar::ONE.neg()), Some(g.neg()));
        let almost = g.to_projective().mul_vartime(&Scalar::ONE.neg());
        assert!(almost.add_affine(&g).is_identity().reveal());
    }

    #[test]
    fn constant_time_windows_at_the_edges() {
        // 0 P is the identity, 1 P is P, and (n - 1) P is -P, for P = G.
        let g = AffinePoint::GENERATOR;
        let gp = g.to_projective();
        assert!(gp.mul_ct(&Scalar::ZERO).is_identity().reveal());
        assert_eq!(gp.mul_ct(&Scalar::ONE).to_affine(), Some(g));
        assert_eq!(gp.mul_ct(&Scalar::ONE.neg()).to_affine(), Some(g.neg()));

        // Any multiple of the identity is the identity.
        let zero = ProjectivePoint::IDENTITY;
        assert!(zero.mul_ct(&Scalar::ONE.neg()).is_identity().reveal());
    }

    #[test]
    fn decompression_picks_the_requested_parity() {
        // Both parities of G's x give G and -G: G's y ends in 0xf5, so it is odd.
        let g = AffinePoint::GENERATOR;
        assert_eq!(AffinePoint::decompress(g.x, true), Some(g));
        assert_eq!(AffinePoint::decompress(g.x, false), Some(g.neg()));
    }

    #[test]
    fn complete_formulas_handle_the_exceptional_inputs() {
        // Identity on either side, P + P, and P + (-P), through all three formulas.
        let g = AffinePoint::GENERATOR;
        let gp = g.to_projective();
        let zero = ProjectivePoint::IDENTITY;
        let two_g = add_reference(Some(g), Some(g));
        assert_eq!(gp.add(&zero).to_affine(), Some(g));
        assert_eq!(zero.add(&gp).to_affine(), Some(g));
        assert_eq!(zero.add_affine(&g).to_affine(), Some(g));
        assert_eq!(gp.add(&gp).to_affine(), two_g);
        assert_eq!(gp.add_affine(&g).to_affine(), two_g);
        assert_eq!(gp.double().to_affine(), two_g);
        assert!(gp.add(&gp.neg()).is_identity().reveal());
        assert!(gp.add_affine(&g.neg()).is_identity().reveal());
        assert!(zero.double().is_identity().reveal());
        assert!(zero.add(&zero).is_identity().reveal());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn formulas_match_the_affine_law(a in arb_point(), b in arb_point()) {
            // Projective sums, mixed sums and doublings equal the textbook law.
            let expected = add_reference(a.to_affine(), b.to_affine());
            prop_assert_eq!(a.add(&b).to_affine(), expected);
            if let Some(affine) = b.to_affine() {
                prop_assert_eq!(a.add_affine(&affine).to_affine(), expected);
            }
            prop_assert_eq!(a.double().to_affine(), add_reference(a.to_affine(), a.to_affine()));
        }

        #[test]
        fn add_and_double_agree(a in arb_point()) {
            // The complete sum of a point with itself is its double.
            prop_assert!(a.add(&a).equals(&a.double()).reveal());
        }

        #[test]
        fn wnaf_matches_double_and_add(k in arb_scalar()) {
            let g = AffinePoint::GENERATOR;
            prop_assert_eq!(g.to_projective().mul_vartime(&k).to_affine(), mul_reference(Some(g), &k));
        }

        #[test]
        fn constant_time_windows_match_variable_time_and_reference(
            base in arb_scalar(),
            k in arb_scalar(),
        ) {
            // Law: k P is the same point by fixed windows, by NAF, and by double-and-add.
            // P = base G is any point, the identity included when base = 0.
            let p = AffinePoint::GENERATOR.to_projective().mul_vartime(&base);
            let windows = p.mul_ct(&k);
            prop_assert!(windows.equals(&p.mul_vartime(&k)).reveal());
            prop_assert_eq!(windows.to_affine(), mul_reference(p.to_affine(), &k));
        }

        #[test]
        fn affine_round_trip(p in arb_point()) {
            // Affine conversion lands on the curve and represents the same point.
            if let Some(affine) = p.to_affine() {
                prop_assert_eq!(AffinePoint::new(affine.x, affine.y), Some(affine));
                prop_assert!(affine.to_projective().equals(&p).reveal());
                prop_assert_eq!(AffinePoint::from_compressed(&affine.to_compressed()), Some(affine));
                prop_assert_eq!(AffinePoint::from_uncompressed(&affine.to_uncompressed()), Some(affine));
            }
        }
    }
}
