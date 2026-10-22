//! Validity of a data column sidecar: its structure, inclusion proof, and cell proofs.

use axiom_kzg::{Bytes48, Cell, CellIndex, Kzg, KzgError};
use axiom_ssz::{CapacityError, Container, GeneralizedIndex, MerkleProof, Root, Ssz};
use axiom_types::{
    ChainConfig, ColumnIndex, Preset,
    fulu::{BeaconBlockBody, DataColumnSidecar},
};
use thiserror::Error;

/// Index of the commitment list among the fields of a block body.
///
/// See `get_generalized_index(BeaconBlockBody, "blob_kzg_commitments")` in the Fulu p2p spec.
const BLOB_KZG_COMMITMENTS_FIELD: usize = 11;

/// A data column sidecar that breaks a structural rule, or blobs that cannot become sidecars.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ColumnError {
    /// The column index is past the last column.
    #[error("column index {index} is not below {columns}")]
    IndexOutOfRange {
        /// The column index.
        index: ColumnIndex,
        /// Columns of the extended blob matrix.
        columns: u64,
    },
    /// The sidecar carries no blob.
    #[error("sidecar of column {0} carries no blob")]
    NoBlobs(ColumnIndex),
    /// The sidecar carries more blobs than the schedule allows.
    #[error("column {column} carries {count} blobs, above the limit of {limit}")]
    TooManyBlobs {
        /// The column index.
        column: ColumnIndex,
        /// Commitments in the sidecar.
        count: usize,
        /// Limit at the sidecar's epoch.
        limit: u64,
    },
    /// The cells, commitments, and proofs of a column differ in number.
    #[error(
        "column {column} has {cells} cells, {commitments} commitments, and {proofs} proofs, which differ in number"
    )]
    LengthMismatch {
        /// The column index.
        column: ColumnIndex,
        /// Cells in the column, one per blob.
        cells: usize,
        /// Commitments, one per blob.
        commitments: usize,
        /// Cell proofs, one per blob.
        proofs: usize,
    },
    /// The commitments are not proven to belong to the block.
    #[error("commitments of column {column} are not proven in block {block_root}")]
    InvalidInclusionProof {
        /// The column index.
        column: ColumnIndex,
        /// Root of the block header the sidecar carries.
        block_root: Root,
    },
    /// A cell is not 64 canonical field elements.
    #[error("cell of blob {blob} in column {column} of block {block_root} is malformed: {source}")]
    MalformedCell {
        /// The column index.
        column: ColumnIndex,
        /// Root of the block header the sidecar carries.
        block_root: Root,
        /// Position of the cell's blob in the commitment list.
        blob: usize,
        /// Why the bytes are not a cell.
        #[source]
        source: KzgError,
    },
    /// A cell does not open its commitment at the column's points.
    ///
    /// A malformed commitment or proof counts as a wrong proof, since either makes the column unusable.
    #[error("cell proofs of column {column} in block {block_root} do not verify")]
    InvalidKzgProofs {
        /// The column index.
        column: ColumnIndex,
        /// Root of the block header the sidecar carries.
        block_root: Root,
    },
    /// The blobs to publish do not match the block's commitments in number.
    #[error("{blobs} blobs do not match {commitments} commitments")]
    BlobCountMismatch {
        /// Blobs offered.
        blobs: usize,
        /// Commitments in the block.
        commitments: usize,
    },
    /// The cell proofs to publish are not one per cell.
    #[error("{proofs} cell proofs offered, {expected} expected")]
    ProofCountMismatch {
        /// Cell proofs offered.
        proofs: usize,
        /// Cells of every blob together.
        expected: usize,
    },
    /// A blob to publish is not 4096 canonical field elements.
    #[error("blob {blob} is malformed: {source}")]
    MalformedBlob {
        /// Position of the blob in the commitment list.
        blob: usize,
        /// Why the bytes are not a blob.
        #[source]
        source: KzgError,
    },
    /// The cell proofs of blobs to publish do not verify.
    #[error("cell proofs of the blobs of block {0} do not verify")]
    InvalidBlobProofs(Root),
    /// A cell does not fit the size the preset gives a cell.
    #[error("cell does not fit the preset: {0}")]
    CellSize(#[source] CapacityError),
    /// The block body yields no branch of the right depth for its commitments.
    #[error("block {0} yields no commitment inclusion proof")]
    NoInclusionProof(Root),
}

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
        let column = sidecar.index;
        if column.0 >= P::NUMBER_OF_COLUMNS {
            return Err(ColumnError::IndexOutOfRange {
                index: column,
                columns: P::NUMBER_OF_COLUMNS,
            });
        }
        let count = sidecar.kzg_commitments.len();
        if count == 0 {
            return Err(ColumnError::NoBlobs(column));
        }
        let epoch = sidecar.signed_block_header.message.slot.epoch::<P>();
        let limit = config.blob_parameters(epoch).max_blobs_per_block;
        if count as u64 > limit {
            return Err(ColumnError::TooManyBlobs {
                column,
                count,
                limit,
            });
        }
        if sidecar.column.len() != count || sidecar.kzg_proofs.len() != count {
            return Err(ColumnError::LengthMismatch {
                column,
                cells: sidecar.column.len(),
                commitments: count,
                proofs: sidecar.kzg_proofs.len(),
            });
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
            Err(ColumnError::InvalidInclusionProof {
                column: sidecar.index,
                block_root: self.block_root(),
            })
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
        let column = sidecar.index;
        let index = CellIndex::new(column.0).map_err(|_| ColumnError::IndexOutOfRange {
            index: column,
            columns: P::NUMBER_OF_COLUMNS,
        })?;

        // A cell holding a non-canonical field element can never verify.
        let cells = sidecar
            .column
            .iter()
            .enumerate()
            .map(|(blob, cell)| {
                Cell::from_bytes(cell.as_ref()).map_err(|source| ColumnError::MalformedCell {
                    column,
                    block_root: self.block_root(),
                    blob,
                    source,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
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
            Ok(false) | Err(_) => Err(ColumnError::InvalidKzgProofs {
                column,
                block_root: self.block_root(),
            }),
        }
    }

    /// Root of the block header the sidecar carries, which names the block in errors.
    fn block_root(self) -> Root {
        self.0.signed_block_header.message.hash_tree_root()
    }
}
