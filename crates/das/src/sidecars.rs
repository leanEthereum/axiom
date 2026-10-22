//! Turning a block and its blobs into the column sidecars that carry them on the network.

use axiom_kzg::{Blob as KzgBlob, Bytes48, CELLS_PER_EXT_BLOB, Cell as KzgCell, CellIndex, Kzg};
use axiom_ssz::{Container, Ssz, Vector};
use axiom_types::{
    Bytes32, ColumnIndex, KzgProof, Preset,
    fulu::{
        BeaconBlockBody, Blob, Cell, DataColumnSidecar, SignedBeaconBlock, SignedBeaconBlockHeader,
    },
};

use crate::ColumnError;

/// Index of the commitment list among the fields of a block body.
///
/// See `get_generalized_index(BeaconBlockBody, "blob_kzg_commitments")` in the Fulu p2p spec.
const BLOB_KZG_COMMITMENTS_FIELD: usize = 11;

/// A signed block about to be published, with its blobs.
///
/// # Overview
///
/// The blobs extend to 128 cells each, and cell `i` of every blob forms column `i`:
///
/// ```text
///                cell 0    cell 1    ...   cell 127
///     blob 0     c_00      c_01      ...   c_0,127
///     blob 1     c_10      c_11      ...   c_1,127
///     column     0         1         ...   127
/// ```
///
/// Each column travels as one sidecar, with the block header and a proof that the commitments are in it.
/// See `get_data_column_sidecars_from_block` in the Fulu validator spec.
#[derive(Clone, Copy, Debug)]
pub struct BlockColumns<'a, P: Preset> {
    /// The block.
    block: &'a SignedBeaconBlock<P>,
}

impl<'a, P: Preset> BlockColumns<'a, P> {
    /// The columns of a block.
    #[must_use]
    pub const fn new(block: &'a SignedBeaconBlock<P>) -> Self {
        Self { block }
    }

    /// Builds every sidecar from the blobs and their cell proofs, after checking the proofs.
    ///
    /// # Arguments
    ///
    /// - `blobs`: the blobs, in commitment order.
    /// - `proofs`: 128 cell proofs per blob, blob after blob, as the beacon API carries them.
    /// - `kzg`: the verifier.
    ///
    /// # Errors
    ///
    /// Fails when the counts disagree with the commitments, or any cell proof does not verify.
    pub fn sidecars(
        &self,
        blobs: &[Blob<P>],
        proofs: &[KzgProof],
        kzg: &Kzg,
    ) -> Result<Vec<DataColumnSidecar<P>>, ColumnError> {
        let body = &self.block.message.body;
        let columns = P::NUMBER_OF_COLUMNS as usize;
        let commitments = body.blob_kzg_commitments.len();
        if blobs.len() != commitments {
            return Err(ColumnError::BlobCountMismatch {
                blobs: blobs.len(),
                commitments,
            });
        }
        if proofs.len() != blobs.len() * columns {
            return Err(ColumnError::ProofCountMismatch {
                proofs: proofs.len(),
                expected: blobs.len() * columns,
            });
        }

        // Extend every blob to its cells.
        let mut cells = Vec::with_capacity(blobs.len());
        for (position, blob) in blobs.iter().enumerate() {
            let blob = KzgBlob::from_bytes(blob.as_ref()).map_err(|source| {
                ColumnError::MalformedBlob {
                    blob: position,
                    source,
                }
            })?;
            cells.push(kzg.compute_cells(&blob));
        }
        self.verify(&cells, proofs, kzg)?;

        // The parts every sidecar shares.
        let header = SignedBeaconBlockHeader {
            message: self.block.message.header(),
            signature: self.block.signature,
        };
        let inclusion_proof = self.inclusion_proof()?;

        // Column i takes cell i and proof i of every blob.
        (0..columns)
            .map(|index| {
                let column_index = ColumnIndex(index as u64);
                let column = cells
                    .iter()
                    .map(|blob_cells| Cell::<P>::try_from(blob_cells[index].to_bytes().as_slice()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(ColumnError::CellSize)?;
                let column_proofs: Vec<KzgProof> = (0..blobs.len())
                    .map(|blob| proofs[blob * columns + index])
                    .collect();
                let mismatch = ColumnError::LengthMismatch {
                    column: column_index,
                    cells: column.len(),
                    commitments,
                    proofs: column_proofs.len(),
                };
                Ok(DataColumnSidecar {
                    index: column_index,
                    column: column.try_into().map_err(|_| mismatch)?,
                    kzg_commitments: body.blob_kzg_commitments.clone(),
                    kzg_proofs: column_proofs.try_into().map_err(|_| mismatch)?,
                    signed_block_header: header.clone(),
                    kzg_commitments_inclusion_proof: inclusion_proof.clone(),
                })
            })
            .collect()
    }

    /// Checks every cell proof in one batched pairing check.
    fn verify(
        self,
        cells: &[Box<[KzgCell; CELLS_PER_EXT_BLOB]>],
        proofs: &[KzgProof],
        kzg: &Kzg,
    ) -> Result<(), ColumnError> {
        let body = &self.block.message.body;
        let mut commitments = Vec::with_capacity(proofs.len());
        let mut indices = Vec::with_capacity(proofs.len());
        let mut flat = Vec::with_capacity(proofs.len());
        for (blob, blob_cells) in cells.iter().enumerate() {
            let commitment = Bytes48::from(body.blob_kzg_commitments[blob].0);
            for (index, cell) in blob_cells.iter().enumerate() {
                commitments.push(commitment);
                indices.push(CellIndex::new(index as u64).map_err(|_| {
                    ColumnError::IndexOutOfRange {
                        index: ColumnIndex(index as u64),
                        columns: P::NUMBER_OF_COLUMNS,
                    }
                })?);
                flat.push(cell.clone());
            }
        }
        let proofs: Vec<Bytes48> = proofs.iter().map(|proof| Bytes48::from(proof.0)).collect();
        match kzg.verify_cell_kzg_proof_batch(&commitments, &indices, &flat, &proofs) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(ColumnError::InvalidBlobProofs(
                self.block.message.hash_tree_root(),
            )),
        }
    }

    /// The branch from the commitment list up to the body root.
    fn inclusion_proof(
        self,
    ) -> Result<Vector<Bytes32, P::KzgCommitmentsInclusionProofDepth>, ColumnError> {
        let body = &self.block.message.body;
        let unavailable = || ColumnError::NoInclusionProof(self.block.message.hash_tree_root());
        let index = BeaconBlockBody::<P>::field_index(BLOB_KZG_COMMITMENTS_FIELD);
        let (_, proof) = body.prove(index).ok_or_else(unavailable)?;
        proof
            .branch
            .into_iter()
            .map(|node| Bytes32(node.0))
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| unavailable())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{ChainConfig, KzgCommitment, Minimal, Slot};

    use super::*;
    use crate::ColumnSidecar;

    /// A block committing to one blob, with that blob's 128 cell proofs.
    ///
    /// The blob's first field elements are 1 and 2, so every cell and proof differs.
    fn fixture(
        kzg: &Kzg,
    ) -> (
        SignedBeaconBlock<Minimal>,
        Vec<Blob<Minimal>>,
        Vec<KzgProof>,
    ) {
        let mut bytes = Blob::<Minimal>::default().as_ref().to_vec();
        bytes[31] = 1;
        bytes[63] = 2;
        let blob = Blob::<Minimal>::try_from(bytes.as_slice()).unwrap();
        let kzg_blob = KzgBlob::from_bytes(blob.as_ref()).unwrap();
        let commitment = kzg.blob_to_kzg_commitment(&kzg_blob);
        let (_, proofs) = kzg.compute_cells_and_kzg_proofs(&kzg_blob);

        let mut block = SignedBeaconBlock::<Minimal>::default();
        block.message.slot = Slot(7);
        block
            .message
            .body
            .blob_kzg_commitments
            .push(KzgCommitment(commitment.0))
            .unwrap();
        let proofs = proofs.iter().map(|proof| KzgProof(proof.0)).collect();
        (block, vec![blob], proofs)
    }

    #[test]
    fn every_built_sidecar_passes_every_receiver_check() {
        let kzg = Kzg::mainnet();
        let (block, blobs, proofs) = fixture(kzg);

        let sidecars = BlockColumns::new(&block)
            .sidecars(&blobs, &proofs, kzg)
            .unwrap();

        // 128 columns, each checked exactly as a peer receiving it would.
        assert_eq!(sidecars.len(), 128);
        let config = ChainConfig::minimal();
        for sidecar in &sidecars {
            let column = ColumnSidecar(sidecar);
            assert_eq!(column.verify_structure(&config), Ok(()));
            assert_eq!(column.verify_inclusion_proof(), Ok(()));
            assert_eq!(column.verify_kzg_proofs(kzg), Ok(()));
        }
    }

    #[test]
    fn a_wrong_proof_or_count_is_refused() {
        let kzg = Kzg::mainnet();
        let (block, blobs, mut proofs) = fixture(kzg);

        // Mutation: drop the last proof, leaving 127 for one blob of 128 cells.
        let last = proofs.pop().unwrap();
        assert_eq!(
            BlockColumns::new(&block).sidecars(&blobs, &proofs, kzg),
            Err(ColumnError::ProofCountMismatch {
                proofs: 127,
                expected: 128,
            })
        );

        // Mutation: offer no blob for the one commitment.
        proofs.push(last);
        assert_eq!(
            BlockColumns::new(&block).sidecars(&[], &proofs, kzg),
            Err(ColumnError::BlobCountMismatch {
                blobs: 0,
                commitments: 1,
            })
        );

        // Mutation: swap two proofs, so cells 0 and 1 carry each other's opening.
        proofs.swap(0, 1);
        assert_eq!(
            BlockColumns::new(&block).sidecars(&blobs, &proofs, kzg),
            Err(ColumnError::InvalidBlobProofs(
                block.message.hash_tree_root()
            ))
        );
    }

    #[test]
    fn a_broken_sidecar_names_its_column_and_block() {
        let kzg = Kzg::mainnet();
        let (block, blobs, proofs) = fixture(kzg);
        let sidecars = BlockColumns::new(&block)
            .sidecars(&blobs, &proofs, kzg)
            .unwrap();
        let block_root = block.message.hash_tree_root();
        let config = ChainConfig::minimal();

        // Mutation: column 5 claims index 128, one past the last column.
        let mut sidecar = sidecars[5].clone();
        sidecar.index = ColumnIndex(128);
        assert_eq!(
            ColumnSidecar(&sidecar).verify_structure(&config),
            Err(ColumnError::IndexOutOfRange {
                index: ColumnIndex(128),
                columns: 128,
            })
        );

        // Mutation: column 5 drops its only commitment.
        let mut sidecar = sidecars[5].clone();
        sidecar.kzg_commitments.clear();
        assert_eq!(
            ColumnSidecar(&sidecar).verify_structure(&config),
            Err(ColumnError::NoBlobs(ColumnIndex(5)))
        );

        // Mutation: column 5 drops its only proof, leaving 1 cell and 1 commitment.
        let mut sidecar = sidecars[5].clone();
        sidecar.kzg_proofs.clear();
        assert_eq!(
            ColumnSidecar(&sidecar).verify_structure(&config),
            Err(ColumnError::LengthMismatch {
                column: ColumnIndex(5),
                cells: 1,
                commitments: 1,
                proofs: 0,
            })
        );

        // Mutation: the first branch node of column 5 is zeroed, so the branch misses the body root.
        let mut sidecar = sidecars[5].clone();
        sidecar.kzg_commitments_inclusion_proof[0] = Bytes32::default();
        assert_eq!(
            ColumnSidecar(&sidecar).verify_inclusion_proof(),
            Err(ColumnError::InvalidInclusionProof {
                column: ColumnIndex(5),
                block_root,
            })
        );

        // Mutation: column 5 carries the proof of column 6.
        let mut sidecar = sidecars[5].clone();
        sidecar.kzg_proofs = sidecars[6].kzg_proofs.clone();
        assert_eq!(
            ColumnSidecar(&sidecar).verify_kzg_proofs(kzg),
            Err(ColumnError::InvalidKzgProofs {
                column: ColumnIndex(5),
                block_root,
            })
        );
    }
}
