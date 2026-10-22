//! Validity of a data column sidecar: its structure, inclusion proof, and cell proofs.

use std::{error::Error, fmt};

use axiom_kzg::{Bytes48, Cell, CellIndex, Kzg};
use axiom_ssz::{Container, GeneralizedIndex, MerkleProof, Root, Ssz};
use axiom_types::{BeaconBlockBody, ChainConfig, DataColumnSidecar, Preset};

/// Index of the commitment list among the fields of a block body.
///
/// See `get_generalized_index(BeaconBlockBody, "blob_kzg_commitments")` in the Fulu p2p spec.
const BLOB_KZG_COMMITMENTS_FIELD: usize = 11;

/// A data column sidecar that breaks a structural rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColumnError {
    /// The column index is past the last column.
    IndexOutOfRange(u64),
    /// The sidecar carries no blob.
    NoBlobs,
    /// The sidecar carries more blobs than the schedule allows.
    TooManyBlobs {
        /// Commitments in the sidecar.
        count: usize,
        /// Limit at the sidecar's epoch.
        limit: u64,
    },
    /// The cells, commitments, and proofs differ in number.
    LengthMismatch,
    /// The commitments are not proven to belong to the block.
    InvalidInclusionProof,
    /// A cell does not open its commitment at the column's points.
    InvalidKzgProofs,
}

impl fmt::Display for ColumnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOutOfRange(index) => write!(f, "column index {index} is out of range"),
            Self::NoBlobs => f.write_str("sidecar carries no blob"),
            Self::TooManyBlobs { count, limit } => {
                write!(f, "{count} blobs exceed the limit of {limit}")
            }
            Self::LengthMismatch => f.write_str("cells, commitments, and proofs differ in number"),
            Self::InvalidInclusionProof => f.write_str("commitments are not in the block"),
            Self::InvalidKzgProofs => f.write_str("cell proofs do not verify"),
        }
    }
}

impl Error for ColumnError {}

/// Checks on a data column sidecar, from its shape to its cell proofs.
#[derive(Clone, Copy, Debug)]
pub struct ColumnSidecar<'a, P: Preset>(pub &'a DataColumnSidecar<P>);

impl<P: Preset> ColumnSidecar<'_, P> {
    /// Checks the index, the blob count, and that the parts line up.
    ///
    /// See `verify_data_column_sidecar` in the Fulu p2p spec.
    ///
    /// # Errors
    ///
    /// Fails at the first broken rule.
    pub fn verify_structure(&self, config: &ChainConfig) -> Result<(), ColumnError> {
        let sidecar = self.0;
        if sidecar.index.0 >= P::NUMBER_OF_COLUMNS {
            return Err(ColumnError::IndexOutOfRange(sidecar.index.0));
        }
        let count = sidecar.kzg_commitments.len();
        if count == 0 {
            return Err(ColumnError::NoBlobs);
        }
        let epoch = sidecar.signed_block_header.message.slot.epoch::<P>();
        let limit = config.blob_parameters(epoch).max_blobs_per_block;
        if count as u64 > limit {
            return Err(ColumnError::TooManyBlobs { count, limit });
        }
        if sidecar.column.len() != count || sidecar.kzg_proofs.len() != count {
            return Err(ColumnError::LengthMismatch);
        }
        Ok(())
    }

    /// Checks the commitments against the block body root, through their merkle branch.
    ///
    /// See `verify_data_column_sidecar_inclusion_proof` in the Fulu p2p spec.
    ///
    /// # Errors
    ///
    /// Fails when the branch does not lead to the header's body root.
    pub fn verify_inclusion_proof(&self) -> Result<(), ColumnError> {
        let sidecar = self.0;
        let index = BeaconBlockBody::<P>::field_index(BLOB_KZG_COMMITMENTS_FIELD);
        let proof = MerkleProof {
            branch: sidecar
                .kzg_commitments_inclusion_proof
                .iter()
                .map(|node| Root(node.0))
                .collect(),
        };
        let valid = proof.verify(
            sidecar.kzg_commitments.hash_tree_root(),
            GeneralizedIndex::at(index.depth() as usize, index.position()),
            sidecar.signed_block_header.message.body_root,
        );
        if valid {
            Ok(())
        } else {
            Err(ColumnError::InvalidInclusionProof)
        }
    }

    /// Checks every cell against its blob's commitment with one batched pairing check.
    ///
    /// All cells of a column sit at the same evaluation points, so one index serves them all.
    /// See `verify_data_column_sidecar_kzg_proofs` in the Fulu p2p spec.
    ///
    /// # Errors
    ///
    /// Fails when a cell is malformed or any proof does not verify.
    pub fn verify_kzg_proofs(&self, kzg: &Kzg) -> Result<(), ColumnError> {
        let sidecar = self.0;
        let index = CellIndex::new(sidecar.index.0)
            .map_err(|_| ColumnError::IndexOutOfRange(sidecar.index.0))?;

        // A cell holding a non-canonical field element can never verify.
        let cells = sidecar
            .column
            .iter()
            .map(|cell| Cell::from_bytes(cell.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ColumnError::InvalidKzgProofs)?;
        let commitments: Vec<Bytes48> = sidecar
            .kzg_commitments
            .iter()
            .map(|commitment| Bytes48::from(commitment.0))
            .collect();
        let proofs: Vec<Bytes48> = sidecar
            .kzg_proofs
            .iter()
            .map(|proof| Bytes48::from(proof.0))
            .collect();
        let indices = vec![index; cells.len()];

        // A malformed point is as fatal as a wrong proof: either way the column is unusable.
        match kzg.verify_cell_kzg_proof_batch(&commitments, &indices, &cells, &proofs) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(ColumnError::InvalidKzgProofs),
        }
    }
}
