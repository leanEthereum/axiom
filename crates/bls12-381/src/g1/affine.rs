//! G1 points in affine coordinates, and their ZCash encodings.

use std::ops::{Mul, Neg};

use super::{B, BETA, G1Projective, GENERATOR_X, GENERATOR_Y};
use crate::{FP_BYTES, Fp, PointDecodeError, Scalar, encoding::Flags};

/// Length of a compressed G1 encoding: the x-coordinate with three flag bits.
pub const G1_COMPRESSED_BYTES: usize = FP_BYTES;

/// Length of an uncompressed G1 encoding: x || y with three flag bits.
pub const G1_UNCOMPRESSED_BYTES: usize = 2 * FP_BYTES;

/// A point of E(F_p) in affine coordinates (x, y), or the point at infinity.
///
/// The type does not by itself guarantee membership in G1.
/// The checked decoders and every group operation on G1 inputs keep that membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Affine {
    /// The x-coordinate, zero at infinity.
    pub(crate) x: Fp,
    /// The y-coordinate, one at infinity.
    pub(crate) y: Fp,
    /// Whether this is the point at infinity.
    pub(crate) infinity: bool,
}

impl G1Affine {
    /// The point at infinity, the group identity.
    pub const IDENTITY: Self = Self {
        x: Fp::ZERO,
        y: Fp::ONE,
        infinity: true,
    };

    /// The standard generator of G1.
    pub const GENERATOR: Self = Self {
        x: GENERATOR_X,
        y: GENERATOR_Y,
        infinity: false,
    };

    /// Whether this is the point at infinity.
    #[must_use]
    pub const fn is_identity(&self) -> bool {
        self.infinity
    }

    /// The affine coordinates, or nothing at infinity.
    #[must_use]
    pub const fn coordinates(&self) -> Option<(Fp, Fp)> {
        if self.infinity {
            None
        } else {
            Some((self.x, self.y))
        }
    }

    /// Whether the point satisfies y^2 = x^3 + 4, or is the point at infinity.
    #[must_use]
    pub fn is_on_curve(&self) -> bool {
        self.infinity || self.y.square() == self.x.square() * self.x + B
    }

    /// Whether the point lies in the order-r subgroup.
    ///
    /// The point must be on the curve.
    ///
    /// # Algorithm
    ///
    /// Scott, "A note on group membership tests for G1, G2 and GT", eprint 2021/1130, section 6.
    /// Correctness for BLS12-381 is proven in eprint 2022/352.
    ///
    /// The endomorphism sigma(x, y) = (beta x, y) acts on G1 as multiplication by -x^2.
    /// Outside G1 the two sides disagree, because the cofactor part has no such eigenvalue.
    ///
    /// ```text
    ///     P in G1  <=>  sigma(P) = [-x^2] P
    /// ```
    ///
    /// Two multiplications by the 64-bit x replace one multiplication by the 255-bit r.
    #[must_use]
    pub fn is_torsion_free(&self) -> bool {
        let point = G1Projective::from(self);
        let minus_x_squared_p = -point.mul_by_x().mul_by_x();
        minus_x_squared_p == G1Projective::from(&self.endomorphism())
    }

    /// The endomorphism sigma(x, y) = (beta x, y).
    fn endomorphism(&self) -> Self {
        Self {
            x: self.x * BETA,
            y: self.y,
            infinity: self.infinity,
        }
    }

    /// Encodes the point as 48 bytes: x with the compression, infinity, and sort flags.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; G1_COMPRESSED_BYTES] {
        // Infinity encodes as flags only, with zero coordinate bits.
        let mut bytes = if self.infinity {
            [0; G1_COMPRESSED_BYTES]
        } else {
            self.x.to_bytes_be()
        };
        Flags {
            compression: true,
            infinity: self.infinity,
            sort: !self.infinity && self.y.is_lexicographically_largest(),
        }
        .put(&mut bytes);
        bytes
    }

    /// Encodes the point as 96 bytes: x || y with the infinity flag.
    #[must_use]
    pub fn to_uncompressed(&self) -> [u8; G1_UNCOMPRESSED_BYTES] {
        let mut bytes = [0; G1_UNCOMPRESSED_BYTES];
        if !self.infinity {
            bytes[..FP_BYTES].copy_from_slice(&self.x.to_bytes_be());
            bytes[FP_BYTES..].copy_from_slice(&self.y.to_bytes_be());
        }
        Flags {
            compression: false,
            infinity: self.infinity,
            sort: false,
        }
        .put(&mut bytes);
        bytes
    }

    /// Decodes a compressed point and checks that it lies in G1.
    pub fn from_compressed(bytes: &[u8; G1_COMPRESSED_BYTES]) -> Result<Self, PointDecodeError> {
        let point = Self::from_compressed_unchecked(bytes)?;
        if !point.is_torsion_free() {
            return Err(PointDecodeError::NotInSubgroup);
        }
        Ok(point)
    }

    /// Decodes a compressed point on the curve, skipping the subgroup check.
    ///
    /// Use it only on trusted input, such as points this library encoded itself.
    pub fn from_compressed_unchecked(
        bytes: &[u8; G1_COMPRESSED_BYTES],
    ) -> Result<Self, PointDecodeError> {
        // Phase 1: separate the flags from the x-coordinate bits.
        let mut x_bytes = *bytes;
        let flags = Flags::take(&mut x_bytes);
        if flags.validate(true, &x_bytes)? {
            return Ok(Self::IDENTITY);
        }

        // Phase 2: x must be a canonical field element.
        let x = Fp::from_bytes_be(&x_bytes).ok_or(PointDecodeError::NonCanonicalCoordinate)?;

        // Phase 3: recover y from the curve equation, y = +-sqrt(x^3 + 4).
        let y = (x.square() * x + B)
            .sqrt()
            .ok_or(PointDecodeError::NotOnCurve)?;

        // Phase 4: the sort flag picks the root.
        let y = if y.is_lexicographically_largest() == flags.sort {
            y
        } else {
            -y
        };
        Ok(Self {
            x,
            y,
            infinity: false,
        })
    }

    /// Decodes an uncompressed point and checks that it lies in G1.
    pub fn from_uncompressed(
        bytes: &[u8; G1_UNCOMPRESSED_BYTES],
    ) -> Result<Self, PointDecodeError> {
        let point = Self::from_uncompressed_unchecked(bytes)?;
        if !point.is_torsion_free() {
            return Err(PointDecodeError::NotInSubgroup);
        }
        Ok(point)
    }

    /// Decodes an uncompressed point on the curve, skipping the subgroup check.
    ///
    /// Use it only on trusted input.
    pub fn from_uncompressed_unchecked(
        bytes: &[u8; G1_UNCOMPRESSED_BYTES],
    ) -> Result<Self, PointDecodeError> {
        // Phase 1: separate the flags from the coordinate bits.
        let mut coordinates = *bytes;
        let flags = Flags::take(&mut coordinates);
        if flags.validate(false, &coordinates)? {
            return Ok(Self::IDENTITY);
        }

        // Phase 2: both coordinates must be canonical.
        let (x_bytes, y_bytes) = coordinates.split_at(FP_BYTES);
        let x = Self::read_coordinate(x_bytes)?;
        let y = Self::read_coordinate(y_bytes)?;

        // Phase 3: the pair must satisfy the curve equation.
        let point = Self {
            x,
            y,
            infinity: false,
        };
        if !point.is_on_curve() {
            return Err(PointDecodeError::NotOnCurve);
        }
        Ok(point)
    }

    /// Reads one 48-byte canonical coordinate.
    fn read_coordinate(bytes: &[u8]) -> Result<Fp, PointDecodeError> {
        let mut array = [0; FP_BYTES];
        array.copy_from_slice(bytes);
        Fp::from_bytes_be(&array).ok_or(PointDecodeError::NonCanonicalCoordinate)
    }
}

impl Default for G1Affine {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl From<&G1Projective> for G1Affine {
    fn from(point: &G1Projective) -> Self {
        // x = X / Z and y = Y / Z; a zero Z is the point at infinity.
        match point.z.invert() {
            Some(z_inverse) => Self {
                x: point.x * z_inverse,
                y: point.y * z_inverse,
                infinity: false,
            },
            None => Self::IDENTITY,
        }
    }
}

impl From<G1Projective> for G1Affine {
    fn from(point: G1Projective) -> Self {
        Self::from(&point)
    }
}

impl Neg for G1Affine {
    type Output = Self;

    fn neg(self) -> Self {
        -&self
    }
}

impl Neg for &G1Affine {
    type Output = G1Affine;

    fn neg(self) -> G1Affine {
        // -(x, y) = (x, -y); infinity keeps its canonical coordinates.
        G1Affine {
            x: self.x,
            y: Fp::conditional_select(&-self.y, &Fp::ONE, self.infinity),
            infinity: self.infinity,
        }
    }
}

impl Mul<Scalar> for G1Affine {
    type Output = G1Projective;

    fn mul(self, scalar: Scalar) -> G1Projective {
        G1Projective::from(&self) * scalar
    }
}

impl Mul<&Scalar> for &G1Affine {
    type Output = G1Projective;

    fn mul(self, scalar: &Scalar) -> G1Projective {
        G1Projective::from(self) * scalar
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_is_on_curve_and_in_subgroup() {
        assert!(G1Affine::GENERATOR.is_on_curve());
        assert!(G1Affine::GENERATOR.is_torsion_free());
    }

    #[test]
    fn generator_compresses_to_the_known_encoding() {
        // ZCash spec: the compressed generator starts 0x97f1d3a7, with the compression bit set.
        let bytes = G1Affine::GENERATOR.to_compressed();
        assert_eq!(&bytes[..4], &[0x97, 0xf1, 0xd3, 0xa7]);
        assert_eq!(G1Affine::from_compressed(&bytes), Ok(G1Affine::GENERATOR));
    }

    #[test]
    fn identity_encodings_are_flag_only() {
        // Compressed infinity is 0xc0 followed by 47 zero bytes.
        let mut compressed = [0_u8; 48];
        compressed[0] = 0xc0;
        assert_eq!(G1Affine::IDENTITY.to_compressed(), compressed);
        assert_eq!(
            G1Affine::from_compressed(&compressed),
            Ok(G1Affine::IDENTITY)
        );

        // Uncompressed infinity is 0x40 followed by 95 zero bytes.
        let mut uncompressed = [0_u8; 96];
        uncompressed[0] = 0x40;
        assert_eq!(G1Affine::IDENTITY.to_uncompressed(), uncompressed);
        assert_eq!(
            G1Affine::from_uncompressed(&uncompressed),
            Ok(G1Affine::IDENTITY)
        );
    }

    #[test]
    fn point_of_order_three_fails_the_subgroup_check() {
        // x = 0 gives y^2 = 4, so (0, 2) is on the curve.
        // Doubling it: the tangent at x = 0 is horizontal, so 2P = -P and P has order 3.
        let point = G1Affine {
            x: Fp::ZERO,
            y: Fp::from_u64(2),
            infinity: false,
        };
        assert!(point.is_on_curve());
        assert!(!point.is_torsion_free());

        // The checked decoder rejects it, the unchecked one accepts it.
        let bytes = point.to_compressed();
        assert_eq!(
            G1Affine::from_compressed(&bytes),
            Err(PointDecodeError::NotInSubgroup)
        );
        assert_eq!(G1Affine::from_compressed_unchecked(&bytes), Ok(point));
    }

    #[test]
    fn x_without_a_curve_point_is_rejected() {
        // x = 1 gives x^3 + 4 = 5, which is not a square mod p.
        let mut bytes = Fp::ONE.to_bytes_be();
        bytes[0] |= 0x80;
        assert_eq!(
            G1Affine::from_compressed(&bytes),
            Err(PointDecodeError::NotOnCurve)
        );
    }

    #[test]
    fn uncompressed_rejects_the_sort_flag() {
        // Mutation: set bit 5 on the uncompressed generator.
        let mut bytes = G1Affine::GENERATOR.to_uncompressed();
        bytes[0] |= 0x20;
        assert_eq!(
            G1Affine::from_uncompressed(&bytes),
            Err(PointDecodeError::UnexpectedSortFlag)
        );
    }

    #[test]
    fn uncompressed_rejects_a_tampered_y() {
        // Mutation: flip the lowest bit of y, leaving the curve.
        let mut bytes = G1Affine::GENERATOR.to_uncompressed();
        bytes[95] ^= 1;
        assert_eq!(
            G1Affine::from_uncompressed(&bytes),
            Err(PointDecodeError::NotOnCurve)
        );
    }

    #[test]
    fn negation_flips_the_sort_flag() {
        // The two points sharing x differ exactly in bit 5 of the first byte.
        let positive = G1Affine::GENERATOR.to_compressed();
        let negative = (-G1Affine::GENERATOR).to_compressed();
        assert_eq!(positive[0] ^ negative[0], 0x20);
        assert_eq!(positive[1..], negative[1..]);
    }
}
