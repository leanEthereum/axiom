//! Partial data columns: a header naming a block's blobs, and some cells of one column.
//!
//! See the Fulu and Gloas partial columns p2p specs.

use axiom_kzg::{Bytes48, Cell as KzgCell, CellIndex, Kzg};
use axiom_ssz::{Container, GeneralizedIndex, MerkleProof, Root, Ssz};
use axiom_types::{
    ColumnIndex, KzgCommitment, KzgProof, Preset,
    fulu::{BeaconBlockBody, Cell, PartialDataColumnHeader},
};

use crate::{Detail, GossipError, fork::Verdict};

/// Index of the commitment list among the fields of a block body.
///
/// See `get_generalized_index(BeaconBlockBody, "blob_kzg_commitments")` in the Fulu p2p spec.
const BLOB_KZG_COMMITMENTS_FIELD: usize = 11;

/// The header of a block's partial columns, common to every column.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PartialHeader<'a, P: Preset>(pub(crate) &'a PartialDataColumnHeader<P>);

impl<P: Preset> PartialHeader<'_, P> {
    /// Whether the commitments sit in the body the block header commits to.
    ///
    /// See `verify_partial_data_column_header_inclusion_proof` in the Fulu partial columns spec.
    pub(crate) fn has_valid_inclusion_proof(self) -> bool {
        let header = self.0;
        let index = BeaconBlockBody::<P>::field_index(BLOB_KZG_COMMITMENTS_FIELD);
        let proof = MerkleProof {
            branch: header
                .kzg_commitments_inclusion_proof
                .iter()
                .map(|node| Root(node.0))
                .collect(),
        };
        proof.verify(
            header.kzg_commitments.hash_tree_root(),
            GeneralizedIndex::at(index.depth() as usize, index.position()),
            header.signed_block_header.message.body_root,
        )
    }
}

/// Some cells of one column, with their proofs and the bitmap of which blobs they belong to.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PartialCells<'a, P: Preset> {
    /// One bit per blob of the block, set where a cell is present.
    pub(crate) present: &'a [bool],
    /// The present cells, in blob order.
    pub(crate) cells: &'a [Cell<P>],
    /// Proofs of the present cells.
    pub(crate) proofs: &'a [KzgProof],
}

impl<P: Preset> PartialCells<'_, P> {
    /// How many cells the bitmap announces.
    pub(crate) fn announced(self) -> usize {
        self.present.iter().filter(|bit| **bit).count()
    }

    /// Rejects a message that says nothing, or whose cells and proofs miscount the bitmap.
    ///
    /// A message with a header may carry no cell, since cells can follow later.
    pub(crate) fn is_well_formed(self, has_header: bool) -> Verdict {
        let announced = self.announced();
        if announced == 0 && !has_header {
            return Err(GossipError::reject("partial message is semantically empty"));
        }
        if self.cells.len() != announced {
            return Err(
                GossipError::reject("number of cells does not match number of set bits").with(
                    Detail::Mismatch {
                        actual: self.cells.len() as u64,
                        expected: announced as u64,
                    },
                ),
            );
        }
        if self.proofs.len() != announced {
            return Err(
                GossipError::reject("number of proofs does not match number of set bits").with(
                    Detail::Mismatch {
                        actual: self.proofs.len() as u64,
                        expected: announced as u64,
                    },
                ),
            );
        }
        Ok(())
    }

    /// Rejects a bitmap whose length is not the block's blob count.
    pub(crate) const fn match_commitments(self, commitments: usize) -> Verdict {
        if self.present.len() != commitments {
            return Err(
                GossipError::reject("bitmap length does not match commitments length").with(
                    Detail::Mismatch {
                        actual: self.present.len() as u64,
                        expected: commitments as u64,
                    },
                ),
            );
        }
        Ok(())
    }

    /// Whether every present cell opens its blob's commitment at the column's evaluation points.
    ///
    /// A malformed cell, commitment, or proof never verifies.
    /// See `verify_partial_data_column_sidecar_kzg_proofs` in the Fulu partial columns spec.
    pub(crate) fn have_valid_kzg_proofs(
        self,
        commitments: &[KzgCommitment],
        column: ColumnIndex,
        kzg: &Kzg,
    ) -> bool {
        let Ok(index) = CellIndex::new(column.0) else {
            return false;
        };
        let Some(selected) = self
            .present
            .iter()
            .enumerate()
            .filter(|(_, bit)| **bit)
            .map(|(blob, _)| {
                commitments
                    .get(blob)
                    .map(|commitment| Bytes48::from(commitment.0))
            })
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        let Ok(cells) = self
            .cells
            .iter()
            .map(|cell| KzgCell::from_bytes(cell.as_ref()))
            .collect::<Result<Vec<_>, _>>()
        else {
            return false;
        };
        let proofs: Vec<Bytes48> = self
            .proofs
            .iter()
            .map(|proof| Bytes48::from(proof.0))
            .collect();
        let indices = vec![index; cells.len()];
        kzg.verify_cell_kzg_proof_batch(&selected, &indices, &cells, &proofs)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;

    use super::*;

    #[test]
    fn cells_and_proofs_must_match_the_bitmap() {
        // Fixture state: a block of 3 blobs, with cells present for blobs 0 and 2.
        let present = [true, false, true];
        let cells = vec![Cell::<Minimal>::default(); 2];
        let proofs = vec![KzgProof::default(); 2];
        let partial = PartialCells::<Minimal> {
            present: &present,
            cells: &cells,
            proofs: &proofs,
        };
        assert_eq!(partial.announced(), 2);
        assert_eq!(partial.is_well_formed(false), Ok(()));
        assert_eq!(partial.match_commitments(3), Ok(()));

        // Mutation: a bitmap for 4 blobs no longer fits a block of 3.
        assert_eq!(
            partial.match_commitments(4),
            Err(GossipError::Reject {
                reason: "bitmap length does not match commitments length",
                detail: Detail::Mismatch {
                    actual: 3,
                    expected: 4,
                },
            })
        );

        // Mutation: one proof missing.
        let short = PartialCells::<Minimal> {
            proofs: &proofs[..1],
            ..partial
        };
        assert_eq!(
            short.is_well_formed(false),
            Err(GossipError::Reject {
                reason: "number of proofs does not match number of set bits",
                detail: Detail::Mismatch {
                    actual: 1,
                    expected: 2,
                },
            })
        );

        // An empty message is allowed only when it carries a header.
        let empty = PartialCells::<Minimal> {
            present: &[false, false, false],
            cells: &[],
            proofs: &[],
        };
        assert_eq!(empty.is_well_formed(true), Ok(()));
        assert_eq!(
            empty.is_well_formed(false),
            Err(GossipError::reject("partial message is semantically empty"))
        );
    }
}
