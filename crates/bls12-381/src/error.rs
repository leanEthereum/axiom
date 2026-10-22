//! Reasons a byte string fails to decode as a curve point.

use thiserror::Error;

/// A byte string that is not the ZCash encoding of a point in the expected group.
///
/// Decoders reject at the first broken rule, in the order the variants appear.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PointDecodeError {
    /// The compression flag disagrees with the length of the encoding.
    ///
    /// Compressed encodings set the top bit of the first byte.
    /// Uncompressed ones clear it.
    #[error("compression flag does not match the encoding length")]
    InvalidCompressionFlag,

    /// The infinity flag is set but other bits are not all zero.
    ///
    /// The point at infinity has exactly one encoding per form.
    #[error("infinity flag set with other bits nonzero")]
    InvalidInfinityEncoding,

    /// An uncompressed encoding sets the sort flag, which only compressed encodings use.
    #[error("sort flag set in an uncompressed encoding")]
    UnexpectedSortFlag,

    /// A coordinate is not below the field modulus.
    #[error("coordinate is not below the field modulus")]
    NonCanonicalCoordinate,

    /// The coordinates do not satisfy the curve equation.
    ///
    /// For a compressed encoding, no y completes the given x.
    #[error("point is not on the curve")]
    NotOnCurve,

    /// The point lies on the curve but outside the prime-order subgroup.
    #[error("point is not in the prime-order subgroup")]
    NotInSubgroup,
}
