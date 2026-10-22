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

    /// A field element of a blob is not below the scalar field modulus.
    ///
    /// Each element has exactly one valid encoding, so commitments stay binding to the bytes.
    #[error("blob field element {index} is not below the scalar field modulus")]
    NonCanonicalBlobElement {
        /// Position of the element in the blob.
        index: usize,
    },

    /// A field element of a cell is not below the scalar field modulus.
    #[error("cell field element {index} is not below the scalar field modulus")]
    NonCanonicalCellElement {
        /// Position of the element in the cell.
        index: usize,
    },

    /// An evaluation point is not below the scalar field modulus.
    #[error("evaluation point is not below the scalar field modulus")]
    NonCanonicalEvaluationPoint,

    /// A claimed evaluation is not below the scalar field modulus.
    #[error("evaluation is not below the scalar field modulus")]
    NonCanonicalEvaluation,

    /// A commitment is not the compressed encoding of a point in G1.
    #[error("commitment {index} is invalid: {source}")]
    InvalidCommitment {
        /// Position of the commitment in its input list, zero for a lone commitment.
        index: usize,
        /// Why the bytes are not a valid point.
        #[source]
        source: PointDecodeError,
    },

    /// A proof is not the compressed encoding of a point in G1.
    #[error("proof {index} is invalid: {source}")]
    InvalidProof {
        /// Position of the proof in its input list, zero for a lone proof.
        index: usize,
        /// Why the bytes are not a valid point.
        #[source]
        source: PointDecodeError,
    },

    /// A blob batch pairs lists that differ in length.
    #[error("{blobs} blobs, {commitments} commitments, and {proofs} proofs differ in number")]
    BlobBatchLengthMismatch {
        /// Number of blobs.
        blobs: usize,
        /// Number of commitments.
        commitments: usize,
        /// Number of proofs.
        proofs: usize,
    },

    /// A cell batch pairs lists that differ in length.
    #[error(
        "{commitments} commitments, {cell_indices} cell indices, {cells} cells, and {proofs} proofs differ in number"
    )]
    CellBatchLengthMismatch {
        /// Number of commitments.
        commitments: usize,
        /// Number of cell indices.
        cell_indices: usize,
        /// Number of cells.
        cells: usize,
        /// Number of proofs.
        proofs: usize,
    },

    /// Recovery pairs cell indices and cells that differ in number.
    #[error("{cell_indices} cell indices and {cells} cells differ in number")]
    RecoveryLengthMismatch {
        /// Number of cell indices.
        cell_indices: usize,
        /// Number of cells.
        cells: usize,
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
    #[error("cell index {next} follows the larger index {previous}")]
    UnsortedCellIndices {
        /// The earlier index.
        previous: u64,
        /// The later, smaller index.
        next: u64,
    },
}
