//! Reasons a KZG input is rejected.

use std::{error::Error, fmt};

use axiom_bls12_381::PointDecodeError;

/// A malformed input to a KZG operation.
///
/// A well-formed input whose proof does not verify is not an error.
/// Verification reports it as a false outcome instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KzgError {
    /// A blob does not hold exactly 4096 field elements of 32 bytes.
    ///
    /// The value is the length received, in bytes.
    InvalidBlobLength(usize),

    /// A cell does not hold exactly 64 field elements of 32 bytes.
    ///
    /// The value is the length received, in bytes.
    InvalidCellLength(usize),

    /// A 32-byte big-endian field element is not below the scalar field modulus.
    ///
    /// Each element has exactly one valid encoding, so commitments stay binding to the bytes.
    NonCanonicalFieldElement,

    /// A commitment is not the compressed encoding of a point in G1.
    InvalidCommitment(PointDecodeError),

    /// A proof is not the compressed encoding of a point in G1.
    InvalidProof(PointDecodeError),

    /// Lists that pair up element by element differ in length.
    LengthMismatch {
        /// Length of the first list, which the others must match.
        expected: usize,
        /// Length of the first list that differs from it.
        actual: usize,
    },

    /// A cell index is not below the 128 cells of an extended blob.
    CellIndexOutOfRange(u64),

    /// Recovery received fewer than half of the cells, or more than all of them.
    ///
    /// The value is the number of cells received.
    InvalidCellCount(usize),

    /// Recovery received the same cell index twice.
    DuplicateCellIndex(u64),

    /// Recovery received cell indices out of ascending order.
    UnsortedCellIndices,
}

impl fmt::Display for KzgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Each message names the rejected input and the broken rule.
        match self {
            Self::InvalidBlobLength(length) => {
                write!(f, "blob has {length} bytes instead of 131072")
            }
            Self::InvalidCellLength(length) => {
                write!(f, "cell has {length} bytes instead of 2048")
            }
            Self::NonCanonicalFieldElement => {
                f.write_str("field element is not below the scalar field modulus")
            }
            Self::InvalidCommitment(error) => write!(f, "invalid commitment: {error}"),
            Self::InvalidProof(error) => write!(f, "invalid proof: {error}"),
            Self::LengthMismatch { expected, actual } => {
                write!(f, "paired lists differ in length: {expected} and {actual}")
            }
            Self::CellIndexOutOfRange(index) => {
                write!(f, "cell index {index} is not below 128")
            }
            Self::InvalidCellCount(count) => {
                write!(f, "recovery needs 64 to 128 cells, got {count}")
            }
            Self::DuplicateCellIndex(index) => write!(f, "cell index {index} appears twice"),
            Self::UnsortedCellIndices => f.write_str("cell indices are not in ascending order"),
        }
    }
}

impl Error for KzgError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // Point decoding failures carry the curve-level reason.
        match self {
            Self::InvalidCommitment(error) | Self::InvalidProof(error) => Some(error),
            _ => None,
        }
    }
}
