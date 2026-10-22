//! Reasons a KZG input is rejected.

use axiom_bls12_381::PointDecodeError;
use thiserror::Error;

/// A malformed input to a KZG operation.
///
/// A well-formed input whose proof does not verify is not an error.
/// Verification reports it as a false outcome instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum KzgError {
    /// A blob does not hold exactly 4096 field elements of 32 bytes.
    ///
    /// The value is the length received, in bytes.
    #[error("blob has {0} bytes instead of 131072")]
    InvalidBlobLength(usize),

    /// A cell does not hold exactly 64 field elements of 32 bytes.
    ///
    /// The value is the length received, in bytes.
    #[error("cell has {0} bytes instead of 2048")]
    InvalidCellLength(usize),

    /// A 32-byte big-endian field element is not below the scalar field modulus.
    ///
    /// Each element has exactly one valid encoding, so commitments stay binding to the bytes.
    #[error("field element is not below the scalar field modulus")]
    NonCanonicalFieldElement,

    /// A commitment is not the compressed encoding of a point in G1.
    #[error("invalid commitment: {0}")]
    InvalidCommitment(#[source] PointDecodeError),

    /// A proof is not the compressed encoding of a point in G1.
    #[error("invalid proof: {0}")]
    InvalidProof(#[source] PointDecodeError),

    /// Lists that pair up element by element differ in length.
    #[error("paired lists differ in length: {expected} and {actual}")]
    LengthMismatch {
        /// Length of the first list, which the others must match.
        expected: usize,
        /// Length of the first list that differs from it.
        actual: usize,
    },

    /// A cell index is not below the 128 cells of an extended blob.
    #[error("cell index {0} is not below 128")]
    CellIndexOutOfRange(u64),

    /// Recovery received fewer than half of the cells, or more than all of them.
    ///
    /// The value is the number of cells received.
    #[error("recovery needs 64 to 128 cells, got {0}")]
    InvalidCellCount(usize),

    /// Recovery received the same cell index twice.
    #[error("cell index {0} appears twice")]
    DuplicateCellIndex(u64),

    /// Recovery received cell indices out of ascending order.
    #[error("cell indices are not in ascending order")]
    UnsortedCellIndices,
}

impl KzgError {
    /// Checks that paired lists all have the length of the first.
    ///
    /// # Errors
    ///
    /// Fails with the first length that differs.
    pub(crate) fn check_paired(expected: usize, others: &[usize]) -> Result<(), Self> {
        match others.iter().find(|actual| **actual != expected) {
            Some(&actual) => Err(Self::LengthMismatch { expected, actual }),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_must_match_the_first_list() {
        // The second list of three, the first of two, is the reported mismatch.
        assert_eq!(
            KzgError::check_paired(2, &[2, 3]),
            Err(KzgError::LengthMismatch {
                expected: 2,
                actual: 3
            })
        );
        assert_eq!(KzgError::check_paired(2, &[2, 2]), Ok(()));
    }
}
