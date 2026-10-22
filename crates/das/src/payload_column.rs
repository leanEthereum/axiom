//! Validity of a Gloas data column sidecar, checked against its block's bid.

use axiom_kzg::{Bytes48, Cell, CellIndex, Kzg};
use axiom_types::{KzgCommitment, Preset, gloas::DataColumnSidecar};

use crate::ColumnError;

/// Checks on a Gloas column, whose commitments sit in its block's bid rather than in the sidecar.
///
/// The bid is signed into the block, so no inclusion proof is needed.
/// See `verify_data_column_sidecar` and its KZG check in the Gloas p2p spec.
#[derive(Clone, Copy, Debug)]
pub struct PayloadColumnSidecar<'a, P: Preset>(pub &'a DataColumnSidecar<P>);

impl<P: Preset> PayloadColumnSidecar<'_, P> {
    /// Checks the column's shape and every cell proof against the bid's commitments.
    ///
    /// # Errors
    ///
    /// Fails when the index is out of range, the column is empty, its lengths disagree,
    /// a cell is malformed, or a proof does not verify.
    pub fn verify(&self, commitments: &[KzgCommitment], kzg: &Kzg) -> Result<(), ColumnError> {
        let sidecar = self.0;
        let column = sidecar.index;
        let block_root = sidecar.beacon_block_root;
        let index = CellIndex::new(column.0)
            .ok()
            .filter(|_| column.0 < P::NUMBER_OF_COLUMNS)
            .ok_or(ColumnError::IndexOutOfRange {
                index: column,
                columns: P::NUMBER_OF_COLUMNS,
            })?;
        if sidecar.column.is_empty() {
            return Err(ColumnError::NoBlobs(column));
        }
        if sidecar.column.len() != commitments.len()
            || sidecar.kzg_proofs.len() != commitments.len()
        {
            return Err(ColumnError::LengthMismatch {
                column,
                cells: sidecar.column.len(),
                commitments: commitments.len(),
                proofs: sidecar.kzg_proofs.len(),
            });
        }

        // A cell holding a non-canonical field element can never verify.
        let cells = sidecar
            .column
            .iter()
            .enumerate()
            .map(|(blob, cell)| {
                Cell::from_bytes(cell.as_ref()).map_err(|source| ColumnError::MalformedCell {
                    column,
                    block_root,
                    blob,
                    source,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let commitments: Vec<Bytes48> = commitments
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
            Ok(false) | Err(_) => Err(ColumnError::InvalidKzgProofs { column, block_root }),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::ByteVector;
    use axiom_types::{ColumnIndex, Minimal, Root};

    use super::*;

    #[test]
    fn the_shape_is_checked_before_any_proof() {
        // Fixture state: a column of block 0x07 with no cell.
        let mut sidecar = DataColumnSidecar::<Minimal> {
            index: ColumnIndex(5),
            beacon_block_root: Root([7; 32]),
            ..Default::default()
        };
        assert_eq!(
            PayloadColumnSidecar(&sidecar).verify(&[], Kzg::mainnet()),
            Err(ColumnError::NoBlobs(ColumnIndex(5)))
        );

        // Mutation: one cell, but the bid commits to two blobs.
        sidecar.column.push(ByteVector::default());
        assert_eq!(
            PayloadColumnSidecar(&sidecar).verify(&[KzgCommitment::ZERO; 2], Kzg::mainnet()),
            Err(ColumnError::LengthMismatch {
                column: ColumnIndex(5),
                cells: 1,
                commitments: 2,
                proofs: 0,
            })
        );

        // Mutation: an index past the last column.
        sidecar.index = ColumnIndex(Minimal::NUMBER_OF_COLUMNS);
        assert_eq!(
            PayloadColumnSidecar(&sidecar).verify(&[KzgCommitment::ZERO], Kzg::mainnet()),
            Err(ColumnError::IndexOutOfRange {
                index: ColumnIndex(Minimal::NUMBER_OF_COLUMNS),
                columns: Minimal::NUMBER_OF_COLUMNS,
            })
        );
    }
}
