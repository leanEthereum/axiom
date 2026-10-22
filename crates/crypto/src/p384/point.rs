//! Points of the curve y^2 = x^3 - 3x + b over GF(p), in affine and projective coordinates.

use super::{field::FieldElement, scalar::Scalar};

/// SEC 1 prefix of a compressed point with even y, per section 2.3.3.
const TAG_EVEN: u8 = 0x02;

/// SEC 1 prefix of a compressed point with odd y.
const TAG_ODD: u8 = 0x03;

/// SEC 1 prefix of an uncompressed point.
const TAG_UNCOMPRESSED: u8 = 0x04;

/// Number of 4-bit windows in a 384-bit scalar.
const WINDOWS: usize = 96;

/// A finite curve point in affine coordinates.
///
/// # Invariants
///
/// The point satisfies y^2 = x^3 - 3x + b, and is never the point at infinity.
/// Since P-384 has cofactor 1, every such point has prime order n.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct AffinePoint {
    /// The x-coordinate.
    pub(super) x: FieldElement,
    /// The y-coordinate.
    pub(super) y: FieldElement,
}

impl AffinePoint {
    /// The generator G, per FIPS 186-4, appendix D.1.2.4.
    pub(super) const GENERATOR: Self = Self {
        x: FieldElement::from_canonical_const([
            0x3a54_5e38_7276_0ab7,
            0x5502_f25d_bf55_296c,
            0x59f7_41e0_8254_2a38,
            0x6e1d_3b62_8ba7_9b98,
            0x8eb1_c71e_f320_ad74,
            0xaa87_ca22_be8b_0537,
        ]),
        y: FieldElement::from_canonical_const([
            0x7a43_1d7c_90ea_0e5f,
            0x0a60_b1ce_1d7e_819d,
            0xe9da_3113_b5f0_b8c0,
            0xf8f4_1dbd_289a_147c,
            0x5d9e_98bf_9292_dc29,
            0x3617_de4a_9626_2c6f,
        ]),
    };

    /// The point with the given coordinates, if it lies on the curve.
    pub(super) fn new(x: FieldElement, y: FieldElement) -> Option<Self> {
        (y.square() == Self::curve_rhs(x)).then_some(Self { x, y })
    }

    /// The point with the given x-coordinate and y parity, if x is on the curve.
    ///
    /// This is point decompression, per SEC 1, section 2.3.4.
    pub(super) fn decompress(x: FieldElement, y_is_odd: bool) -> Option<Self> {
        // The right-hand side has a root exactly when x is the abscissa of a point.
        let y = Self::curve_rhs(x).sqrt()?;

        // The two roots y and p - y have opposite parity.
        // No root is zero: a point with y = 0 has order 2, and the group order is odd.
        let y = if y.is_odd() == y_is_odd { y } else { y.neg() };
        Some(Self { x, y })
    }

    /// Decodes the 49-byte SEC 1 compressed form, prefix 0x02 or 0x03 then x.
    ///
    /// Refuses a wrong prefix, x not below p, or x with no point on the curve.
    pub(super) fn from_compressed(bytes: &[u8; 49]) -> Option<Self> {
        let (&[tag], x) = bytes.split_first_chunk::<1>()?;
        let y_is_odd = match tag {
            TAG_EVEN => false,
            TAG_ODD => true,
            _ => return None,
        };
        let x = FieldElement::from_bytes(x.try_into().ok()?)?;
        Self::decompress(x, y_is_odd)
    }

    /// Decodes the 97-byte SEC 1 uncompressed form, prefix 0x04 then x then y.
    ///
    /// Refuses a wrong prefix, a coordinate not below p, or a point off the curve.
    pub(super) fn from_uncompressed(bytes: &[u8; 97]) -> Option<Self> {
        let ([TAG_UNCOMPRESSED], coordinates) = bytes.split_first_chunk::<1>()? else {
            return None;
        };
        let (coordinates, _) = coordinates.as_chunks::<48>();
        let x = FieldElement::from_bytes(&coordinates[0])?;
        let y = FieldElement::from_bytes(&coordinates[1])?;
        Self::new(x, y)
    }

    /// The 49-byte SEC 1 compressed form, per section 2.3.3.
    pub(super) fn to_compressed(self) -> [u8; 49] {
        let mut out = [0_u8; 49];
        out[0] = if self.y.is_odd() { TAG_ODD } else { TAG_EVEN };
        out[1..].copy_from_slice(&self.x.to_bytes());
        out
    }

    /// The 97-byte SEC 1 uncompressed form.
    pub(super) fn to_uncompressed(self) -> [u8; 97] {
        let mut out = [0_u8; 97];
        out[0] = TAG_UNCOMPRESSED;
        out[1..49].copy_from_slice(&self.x.to_bytes());
        out[49..].copy_from_slice(&self.y.to_bytes());
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
}

/// A curve point in homogeneous projective coordinates, the point at infinity included.
///
/// # Overview
///
/// (X : Y : Z) stands for the affine point (X / Z, Y / Z).
/// The point at infinity is (0 : 1 : 0).
///
/// The complete formulas of Renes, Costello and Batina need these coordinates.
/// They hold for every pair of inputs, so the double-scalar loop needs no special cases.
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
    pub(super) fn is_identity(&self) -> bool {
        // On the curve, Z = 0 forces X = 0, the single point at infinity.
        self.z.is_zero()
    }

    /// The affine form, or nothing at infinity.
    #[cfg(test)]
    pub(super) fn to_affine(self) -> Option<AffinePoint> {
        if self.is_identity() {
            return None;
        }
        // x = X / Z, y = Y / Z.
        let z_inv = self.z.invert();
        Some(AffinePoint {
            x: self.x.mul(z_inv),
            y: self.y.mul(z_inv),
        })
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
    pub(super) fn equals(&self, other: &Self) -> bool {
        // Cross-multiply, so different Z scalings agree.
        // Two points at infinity agree too, and a finite point never equals infinity.
        match (self.is_identity(), other.is_identity()) {
            (true, true) => true,
            (false, false) => {
                self.x.mul(other.z) == other.x.mul(self.z)
                    && self.y.mul(other.z) == other.y.mul(self.z)
            }
            _ => false,
        }
    }

    /// The multiples 0 P to 15 P, the identity first.
    fn multiples(&self) -> [Self; 16] {
        let mut table = [Self::IDENTITY; 16];
        for j in 1..16 {
            table[j] = table[j - 1].add(self);
        }
        table
    }

    /// The point times a public scalar, by fixed 4-bit windows.
    ///
    /// Used only on public inputs: each digit indexes the table and may skip its addition.
    #[cfg(test)]
    pub(super) fn mul_vartime(&self, k: &Scalar) -> Self {
        Self::IDENTITY.double_mul_vartime(&Scalar::ZERO, self, k)
    }

    /// a P + b Q for public scalars and public points, with P the receiver.
    ///
    /// # Algorithm
    ///
    /// Interleaved fixed 4-bit windows, the trick attributed to Shamir by ElGamal, 1985.
    ///
    /// ```text
    /// acc = 16 acc + a_i P + b_i Q    for each window i, high to low
    /// ```
    ///
    /// The two scalars share one chain of 384 doublings.
    /// Zero digits skip their addition, so the time depends on the scalars: verification only.
    pub(super) fn double_mul_vartime(&self, a: &Scalar, q: &Self, b: &Scalar) -> Self {
        let left = self.multiples();
        let right = q.multiples();

        let mut acc = Self::IDENTITY;
        for window in (0..WINDOWS).rev() {
            acc = acc.double().double().double().double();
            let (da, db) = (a.nibble(window), b.nibble(window));
            if da != 0 {
                acc = acc.add(&left[da]);
            }
            if db != 0 {
                acc = acc.add(&right[db]);
            }
        }
        acc
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::array;

    use proptest::prelude::*;

    use super::*;
    use crate::p384::scalar::tests::arb_scalar;

    /// The affine group law with inversions, the textbook reference, none standing for infinity.
    fn add_reference(a: Option<AffinePoint>, b: Option<AffinePoint>) -> Option<AffinePoint> {
        let (Some(a), Some(b)) = (a, b) else {
            return a.or(b);
        };
        let slope = if a.x == b.x {
            if a.y != b.y || a.y.is_zero() {
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
        for bit in (0..384).rev() {
            acc = add_reference(acc, acc);
            if k.bit(bit) == 1 {
                acc = add_reference(acc, point);
            }
        }
        acc
    }

    /// A random point: a random multiple of the generator, infinity included.
    fn arb_point() -> impl Strategy<Value = ProjectivePoint> {
        arb_scalar().prop_map(|k| AffinePoint::GENERATOR.to_projective().mul_vartime(&k))
    }

    /// Decodes a hex string of known length.
    fn hex<const N: usize>(text: &str) -> [u8; N] {
        array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn generator_lies_on_the_curve_and_has_order_n() {
        let g = AffinePoint::GENERATOR;
        assert_eq!(AffinePoint::new(g.x, g.y), Some(g));

        // (n - 1) G = -G, so n G = 0.
        assert_eq!(mul_reference(Some(g), &Scalar::ONE.neg()), Some(g.neg()));
        let almost = g.to_projective().mul_vartime(&Scalar::ONE.neg());
        assert!(almost.add(&g.to_projective()).is_identity());
    }

    #[test]
    fn known_multiples() {
        // 2 G and 3 G, checked against affine arithmetic over big integers.
        let g = AffinePoint::GENERATOR.to_projective();
        let two = g.double().to_affine().unwrap();
        assert_eq!(
            two.to_uncompressed()[1..],
            hex::<96>(
                "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df618e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80"
            )
        );
        let three = g.add(&g).add(&g).to_affine().unwrap();
        assert_eq!(
            three.to_uncompressed()[1..],
            hex::<96>(
                "077a41d4606ffa1464793c7e5fdc7d98cb9d3910202dcd06bea4f240d3566da6b408bbae5026580d02d7e5c70500c831c995f7ca0b0c42837d0bbe9602a9fc998520b41c85115aa5f7684c0edc111eacc24abd6be4b5d298b65f28600a2f1df1"
            )
        );
    }

    #[test]
    fn decompression_picks_the_requested_parity() {
        // G's y ends in 0x5f, so it is odd.
        let g = AffinePoint::GENERATOR;
        assert_eq!(AffinePoint::decompress(g.x, true), Some(g));
        assert_eq!(AffinePoint::decompress(g.x, false), Some(g.neg()));
    }

    #[test]
    fn complete_formulas_handle_the_exceptional_inputs() {
        // Identity on either side, P + P, and P + (-P).
        let g = AffinePoint::GENERATOR;
        let gp = g.to_projective();
        let minus = g.neg().to_projective();
        let zero = ProjectivePoint::IDENTITY;
        let two_g = add_reference(Some(g), Some(g));
        assert_eq!(gp.add(&zero).to_affine(), Some(g));
        assert_eq!(zero.add(&gp).to_affine(), Some(g));
        assert_eq!(gp.add(&gp).to_affine(), two_g);
        assert_eq!(gp.double().to_affine(), two_g);
        assert!(gp.add(&minus).is_identity());
        assert!(zero.double().is_identity());
        assert!(zero.add(&zero).is_identity());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn formulas_match_the_affine_law(a in arb_point(), b in arb_point()) {
            // Projective sums and doublings equal the textbook law.
            let expected = add_reference(a.to_affine(), b.to_affine());
            prop_assert_eq!(a.add(&b).to_affine(), expected);
            prop_assert_eq!(a.double().to_affine(), add_reference(a.to_affine(), a.to_affine()));
            prop_assert!(a.add(&a).equals(&a.double()));
        }

        #[test]
        fn windows_match_double_and_add(k in arb_scalar()) {
            let g = AffinePoint::GENERATOR;
            prop_assert_eq!(g.to_projective().mul_vartime(&k).to_affine(), mul_reference(Some(g), &k));
        }

        #[test]
        fn double_multiplication_matches_two_products(
            a in arb_scalar(),
            b in arb_scalar(),
            c in arb_scalar(),
        ) {
            // a G + b Q with Q = c G equals (a + b c) G.
            let g = AffinePoint::GENERATOR.to_projective();
            let q = g.mul_vartime(&c);
            let expected = g.mul_vartime(&a.add(b.mul(c)));
            prop_assert!(g.double_mul_vartime(&a, &q, &b).equals(&expected));
        }

        #[test]
        fn affine_round_trip(p in arb_point()) {
            // Affine conversion lands on the curve, and both encodings round-trip.
            if let Some(affine) = p.to_affine() {
                prop_assert_eq!(AffinePoint::new(affine.x, affine.y), Some(affine));
                prop_assert!(affine.to_projective().equals(&p));
                prop_assert_eq!(AffinePoint::from_compressed(&affine.to_compressed()), Some(affine));
                prop_assert_eq!(AffinePoint::from_uncompressed(&affine.to_uncompressed()), Some(affine));
            }
        }
    }
}
