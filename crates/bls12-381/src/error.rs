//! Reasons a byte string fails to decode as a curve point.

use std::{error::Error, fmt};

/// A byte string that is not the ZCash encoding of a point in the expected group.
///
/// Decoders reject at the first broken rule, in the order the variants appear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PointDecodeError {
    /// The compression flag disagrees with the length of the encoding.
    ///
    /// Compressed encodings set the top bit of the first byte; uncompressed ones clear it.
    InvalidCompressionFlag,

    /// The infinity flag is set but other bits are not all zero.
    ///
    /// The point at infinity has exactly one encoding per form.
    InvalidInfinityEncoding,

    /// An uncompressed encoding sets the sort flag, which only compressed encodings use.
    UnexpectedSortFlag,

    /// A coordinate is not below the field modulus.
    NonCanonicalCoordinate,

    /// The coordinates do not satisfy the curve equation.
    ///
    /// For a compressed encoding, no y completes the given x.
    NotOnCurve,

    /// The point lies on the curve but outside the prime-order subgroup.
    NotInSubgroup,
}

impl fmt::Display for PointDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidCompressionFlag => "compression flag does not match the encoding length",
            Self::InvalidInfinityEncoding => "infinity flag set with other bits nonzero",
            Self::UnexpectedSortFlag => "sort flag set in an uncompressed encoding",
            Self::NonCanonicalCoordinate => "coordinate is not below the field modulus",
            Self::NotOnCurve => "point is not on the curve",
            Self::NotInSubgroup => "point is not in the prime-order subgroup",
        })
    }
}

impl Error for PointDecodeError {}
