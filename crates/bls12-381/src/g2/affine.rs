//! G2 points in affine coordinates, and their ZCash encodings.

use std::ops::{Mul, Neg};

use super::{B, G2Projective, GENERATOR_X, GENERATOR_Y};
use crate::{FP_BYTES, Fp, Fp2, PointDecodeError, Scalar, encoding::Flags};

/// Length of a compressed G2 encoding: x = x_0 + x_1 u as x_1 || x_0, with three flag bits.
pub const G2_COMPRESSED_BYTES: usize = 2 * FP_BYTES;

/// Length of an uncompressed G2 encoding: x_1 || x_0 || y_1 || y_0, with three flag bits.
pub const G2_UNCOMPRESSED_BYTES: usize = 4 * FP_BYTES;

/// A point of E'(F_{p^2}) in affine coordinates (x, y), or the point at infinity.
///
/// The type does not by itself guarantee membership in G2.
/// The checked decoders and every group operation on G2 inputs keep that membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2Affine {
    /// The x-coordinate, zero at infinity.
    pub(crate) x: Fp2,
    /// The y-coordinate, one at infinity.
    pub(crate) y: Fp2,
    /// Whether this is the point at infinity.
    pub(crate) infinity: bool,
}

impl G2Affine {
    /// The point at infinity, the group identity.
    pub const IDENTITY: Self = Self {
        x: Fp2::ZERO,
        y: Fp2::ONE,
        infinity: true,
    };

    /// The standard generator of G2.
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
    pub const fn coordinates(&self) -> Option<(Fp2, Fp2)> {
        // Infinity has no affine coordinates.
        if self.infinity {
            None
        } else {
            Some((self.x, self.y))
        }
    }

    /// Whether the point satisfies y^2 = x^3 + 4(1 + u), or is the point at infinity.
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
    /// Scott, "A note on group membership tests for G1, G2 and GT", eprint 2021/1130, section 4.
    ///
    /// The endomorphism psi acts on G2 as multiplication by p, and p = x mod r.
    /// For BLS12 curves the converse holds too: psi(P) = x P holds only inside G2.
    ///
    /// ```text
    ///     P in G2  <=>  psi(P) = [x] P
    /// ```
    ///
    /// One multiplication by the 64-bit x replaces one by the 255-bit r.
    #[must_use]
    pub fn is_torsion_free(&self) -> bool {
        let point = G2Projective::from(self);
        point.psi() == point.mul_by_x()
    }

    /// Encodes the point as 96 bytes: x_1 || x_0 with the compression, infinity, and sort flags.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; G2_COMPRESSED_BYTES] {
        // Infinity keeps all coordinate bytes zero.
        let mut bytes = [0; G2_COMPRESSED_BYTES];
        if !self.infinity {
            Self::write_fp2(&self.x, &mut bytes);
        }
        // The sort flag records which of +-y the point uses.
        Flags {
            compression: true,
            infinity: self.infinity,
            sort: !self.infinity && self.y.is_lexicographically_largest(),
        }
        .put(&mut bytes);
        bytes
    }

    /// Encodes the point as 192 bytes: x_1 || x_0 || y_1 || y_0 with the infinity flag.
    #[must_use]
    pub fn to_uncompressed(&self) -> [u8; G2_UNCOMPRESSED_BYTES] {
        // Infinity keeps all coordinate bytes zero.
        let mut bytes = [0; G2_UNCOMPRESSED_BYTES];
        if !self.infinity {
            let (x_bytes, y_bytes) = bytes.split_at_mut(2 * FP_BYTES);
            Self::write_fp2(&self.x, x_bytes);
            Self::write_fp2(&self.y, y_bytes);
        }
        // Only the infinity flag can be set in this form.
        Flags {
            compression: false,
            infinity: self.infinity,
            sort: false,
        }
        .put(&mut bytes);
        bytes
    }

    /// Decodes a compressed point and checks that it lies in G2.
    pub fn from_compressed(bytes: &[u8; G2_COMPRESSED_BYTES]) -> Result<Self, PointDecodeError> {
        // Decode and check the curve equation first, then the subgroup.
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
        bytes: &[u8; G2_COMPRESSED_BYTES],
    ) -> Result<Self, PointDecodeError> {
        // Phase 1: separate the flags from the coordinate bits.
        let mut x_bytes = *bytes;
        let flags = Flags::take(&mut x_bytes);
        if flags.validate(true, &x_bytes)? {
            return Ok(Self::IDENTITY);
        }

        // Phase 2: both halves of x must be canonical.
        let x = Self::read_fp2(&x_bytes)?;

        // Phase 3: recover y = +-sqrt(x^3 + b').
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

    /// Decodes an uncompressed point and checks that it lies in G2.
    pub fn from_uncompressed(
        bytes: &[u8; G2_UNCOMPRESSED_BYTES],
    ) -> Result<Self, PointDecodeError> {
        // Decode and check the curve equation first, then the subgroup.
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
        bytes: &[u8; G2_UNCOMPRESSED_BYTES],
    ) -> Result<Self, PointDecodeError> {
        // Phase 1: separate the flags from the coordinate bits.
        let mut coordinates = *bytes;
        let flags = Flags::take(&mut coordinates);
        if flags.validate(false, &coordinates)? {
            return Ok(Self::IDENTITY);
        }

        // Phase 2: all four base-field coordinates must be canonical.
        let (x_bytes, y_bytes) = coordinates.split_at(2 * FP_BYTES);
        let point = Self {
            x: Self::read_fp2(x_bytes)?,
            y: Self::read_fp2(y_bytes)?,
            infinity: false,
        };

        // Phase 3: the pair must satisfy the curve equation.
        if !point.is_on_curve() {
            return Err(PointDecodeError::NotOnCurve);
        }
        Ok(point)
    }

    /// Writes c1 || c0 into 96 bytes, the u coefficient first as the ZCash format requires.
    fn write_fp2(value: &Fp2, out: &mut [u8]) {
        out[..FP_BYTES].copy_from_slice(&value.c1.to_bytes_be());
        out[FP_BYTES..2 * FP_BYTES].copy_from_slice(&value.c0.to_bytes_be());
    }

    /// Reads c1 || c0 from 96 bytes, rejecting a non-canonical half.
    fn read_fp2(bytes: &[u8]) -> Result<Fp2, PointDecodeError> {
        // Each half must be a canonical base-field element.
        let read = |chunk: &[u8]| {
            let mut array = [0; FP_BYTES];
            array.copy_from_slice(chunk);
            Fp::from_bytes_be(&array).ok_or(PointDecodeError::NonCanonicalCoordinate)
        };
        // The u coefficient comes first on the wire.
        let c1 = read(&bytes[..FP_BYTES])?;
        let c0 = read(&bytes[FP_BYTES..2 * FP_BYTES])?;
        Ok(Fp2::new(c0, c1))
    }
}

impl Default for G2Affine {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl From<&G2Projective> for G2Affine {
    fn from(point: &G2Projective) -> Self {
        // x = X / Z and y = Y / Z.
        // A zero Z is the point at infinity.
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

impl From<G2Projective> for G2Affine {
    fn from(point: G2Projective) -> Self {
        Self::from(&point)
    }
}

impl Neg for G2Affine {
    type Output = Self;

    fn neg(self) -> Self {
        -&self
    }
}

impl Neg for &G2Affine {
    type Output = G2Affine;

    fn neg(self) -> G2Affine {
        // -(x, y) = (x, -y).
        // Infinity keeps its canonical coordinates.
        G2Affine {
            x: self.x,
            y: Fp2::conditional_select(&-self.y, &Fp2::ONE, self.infinity),
            infinity: self.infinity,
        }
    }
}

impl Mul<Scalar> for G2Affine {
    type Output = G2Projective;

    fn mul(self, scalar: Scalar) -> G2Projective {
        G2Projective::from(&self) * scalar
    }
}

impl Mul<&Scalar> for &G2Affine {
    type Output = G2Projective;

    fn mul(self, scalar: &Scalar) -> G2Projective {
        G2Projective::from(self) * scalar
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_is_on_curve_and_in_subgroup() {
        assert!(G2Affine::GENERATOR.is_on_curve());
        assert!(G2Affine::GENERATOR.is_torsion_free());
    }

    #[test]
    fn generator_compresses_to_the_known_encoding() {
        // ZCash spec: the compressed generator starts 0x93e02b60, the u coefficient of x with flags.
        let bytes = G2Affine::GENERATOR.to_compressed();
        assert_eq!(&bytes[..4], &[0x93, 0xe0, 0x2b, 0x60]);
        assert_eq!(G2Affine::from_compressed(&bytes), Ok(G2Affine::GENERATOR));
    }

    #[test]
    fn identity_encodings_are_flag_only() {
        // Compressed infinity is 0xc0 followed by 95 zero bytes.
        let mut compressed = [0_u8; 96];
        compressed[0] = 0xc0;
        assert_eq!(G2Affine::IDENTITY.to_compressed(), compressed);
        assert_eq!(
            G2Affine::from_compressed(&compressed),
            Ok(G2Affine::IDENTITY)
        );

        // Uncompressed infinity is 0x40 followed by 191 zero bytes.
        let mut uncompressed = [0_u8; 192];
        uncompressed[0] = 0x40;
        assert_eq!(G2Affine::IDENTITY.to_uncompressed(), uncompressed);
        assert_eq!(
            G2Affine::from_uncompressed(&uncompressed),
            Ok(G2Affine::IDENTITY)
        );
    }

    #[test]
    fn non_canonical_half_is_rejected() {
        // Mutation: replace x_0, the second 48 bytes, with p itself.
        let mut bytes = G2Affine::GENERATOR.to_compressed();
        let p = [
            0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b,
            0xac, 0xd7, 0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0,
            0xf6, 0xb0, 0xf6, 0x24, 0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe,
            0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
        ];
        bytes[48..].copy_from_slice(&p);
        assert_eq!(
            G2Affine::from_compressed(&bytes),
            Err(PointDecodeError::NonCanonicalCoordinate)
        );
    }

    #[test]
    fn uncompressed_rejects_a_tampered_y() {
        // Mutation: flip the lowest bit of y_0, leaving the curve.
        let mut bytes = G2Affine::GENERATOR.to_uncompressed();
        bytes[191] ^= 1;
        assert_eq!(
            G2Affine::from_uncompressed(&bytes),
            Err(PointDecodeError::NotOnCurve)
        );
    }

    #[test]
    fn negation_flips_the_sort_flag() {
        // The two points sharing x differ exactly in bit 5 of the first byte.
        let positive = G2Affine::GENERATOR.to_compressed();
        let negative = (-G2Affine::GENERATOR).to_compressed();
        assert_eq!(positive[0] ^ negative[0], 0x20);
        assert_eq!(positive[1..], negative[1..]);
    }
}
