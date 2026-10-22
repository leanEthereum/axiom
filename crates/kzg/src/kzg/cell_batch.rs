//! The inputs of one cell batch verification, with commitments deduplicated.

use std::collections::HashMap;

use axiom_bls12_381::Scalar;

use crate::{
    Bytes48, CELLS_PER_EXT_BLOB, Cell, CellIndex, FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL,
    KzgError, transcript::Transcript,
};

/// Domain tag of the cell batch coefficient, RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN in the Fulu spec.
const RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN: &[u8; 16] = b"RCKZGCBATCH__V1_";

/// Cells with their indices and proofs, each naming its commitment by position in a distinct list.
///
/// Commitments repeat across the cells of one blob, so the spec hashes and weights each only once.
#[derive(Clone, Debug)]
pub(super) struct CellBatch<'a> {
    /// The distinct commitments, in order of first appearance.
    commitments: Vec<&'a Bytes48>,
    /// For each distinct commitment, the first cell that names it.
    first_cells: Vec<usize>,
    /// For each cell, the position of its commitment in the distinct list.
    commitment_indices: Vec<usize>,
    /// For each cell, its position in the extended blob.
    cell_indices: &'a [CellIndex],
    /// The cells.
    cells: &'a [Cell],
    /// For each cell, its proof.
    proofs: &'a [Bytes48],
}

impl<'a> CellBatch<'a> {
    /// Pairs up the four lists entry by entry and deduplicates the commitments by their bytes.
    ///
    /// ```text
    ///     commitments          [A, B, A, C]
    ///     distinct             [A, B, C]
    ///     commitment indices   [0, 1, 0, 2]
    /// ```
    ///
    /// # Errors
    ///
    /// Fails when the lists differ in length.
    pub(super) fn new(
        commitments: &'a [Bytes48],
        cell_indices: &'a [CellIndex],
        cells: &'a [Cell],
        proofs: &'a [Bytes48],
    ) -> Result<Self, KzgError> {
        let cell_count = cells.len();
        if commitments.len() != cell_count
            || cell_indices.len() != cell_count
            || proofs.len() != cell_count
        {
            return Err(KzgError::CellBatchLengthMismatch {
                commitments: commitments.len(),
                cell_indices: cell_indices.len(),
                cells: cell_count,
                proofs: proofs.len(),
            });
        }
        let mut distinct: Vec<&Bytes48> = Vec::new();
        let mut first_cells = Vec::new();
        let mut positions: HashMap<&Bytes48, usize> = HashMap::new();
        let commitment_indices = commitments
            .iter()
            .enumerate()
            .map(|(cell, commitment)| {
                *positions.entry(commitment).or_insert_with(|| {
                    distinct.push(commitment);
                    first_cells.push(cell);
                    distinct.len() - 1
                })
            })
            .collect();
        Ok(Self {
            commitments: distinct,
            first_cells,
            commitment_indices,
            cell_indices,
            cells,
            proofs,
        })
    }

    /// Number of cells.
    pub(super) const fn len(&self) -> usize {
        self.cells.len()
    }

    /// The distinct commitments, in order of first appearance.
    pub(super) fn commitments(&self) -> &[&'a Bytes48] {
        &self.commitments
    }

    /// For each distinct commitment, the first cell that names it.
    ///
    /// An invalid commitment is reported at this position in the input list.
    pub(super) fn first_cells(&self) -> &[usize] {
        &self.first_cells
    }

    /// The cell positions, one per cell.
    pub(super) const fn cell_indices(&self) -> &'a [CellIndex] {
        self.cell_indices
    }

    /// The proofs, one per cell.
    pub(super) const fn proofs(&self) -> &'a [Bytes48] {
        self.proofs
    }

    /// The coefficient r of the batch, compute_verify_cell_kzg_proof_batch_challenge in the Fulu spec.
    ///
    /// ```text
    ///     SHA-256( tag || 4096 || 64 || #commitments || #cells          (u64 each)
    ///              || commitments
    ///              || (commitment index || cell index || cell || proof) for each cell )  mod r
    /// ```
    pub(super) fn challenge(&self) -> Scalar {
        let mut transcript = Transcript::new(RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN);
        transcript.append_u64(FIELD_ELEMENTS_PER_BLOB as u64);
        transcript.append_u64(FIELD_ELEMENTS_PER_CELL as u64);
        transcript.append_u64(self.commitments.len() as u64);
        transcript.append_u64(self.cell_indices.len() as u64);
        for commitment in &self.commitments {
            transcript.append(commitment.0);
        }
        let rows = self
            .commitment_indices
            .iter()
            .zip(self.cell_indices)
            .zip(self.cells)
            .zip(self.proofs);
        for (((commitment_index, cell_index), cell), proof) in rows {
            transcript.append_u64(*commitment_index as u64);
            transcript.append_u64(cell_index.get());
            // Cells hold canonical elements, so re-encoding gives back the bytes received.
            transcript.append(cell.to_bytes());
            transcript.append(proof.0);
        }
        transcript.challenge()
    }

    /// The weight of each distinct commitment: the sum of r^k over the cells that name it.
    pub(super) fn commitment_weights(&self, r_powers: &[Scalar]) -> Vec<Scalar> {
        let mut weights = vec![Scalar::ZERO; self.commitments.len()];
        for (index, power) in self.commitment_indices.iter().zip(r_powers) {
            weights[*index] += power;
        }
        weights
    }

    /// The sum of r^k e_k over the cells of each column, or none for a column without cells.
    ///
    /// Cells of one column share a coset, so their weighted sum has a single interpolant.
    pub(super) fn weighted_columns(
        &self,
        r_powers: &[Scalar],
    ) -> Vec<Option<[Scalar; FIELD_ELEMENTS_PER_CELL]>> {
        let mut columns = vec![None; CELLS_PER_EXT_BLOB];
        for ((index, cell), power) in self.cell_indices.iter().zip(self.cells).zip(r_powers) {
            let column: &mut [Scalar; FIELD_ELEMENTS_PER_CELL] =
                columns[index.position()].get_or_insert([Scalar::ZERO; FIELD_ELEMENTS_PER_CELL]);
            for (sum, value) in column.iter_mut().zip(cell.evaluations()) {
                *sum += value * power;
            }
        }
        columns
    }
}

#[cfg(test)]
mod tests {
    use axiom_yaml::Yaml;
    use proptest::{collection::vec, prelude::*, sample::Index};

    use super::*;
    use crate::{
        Blob, Kzg,
        blob::tests::blob_from_seed,
        test_vectors::{cases, points},
    };

    #[test]
    fn challenge_matches_vectors() {
        // Each case lists deduplicated commitments, then one row per cell.
        for case in cases("compute_verify_cell_kzg_proof_batch_challenge", 10) {
            let input = case.get("input").unwrap();
            let sequence = |key: &str| input.get(key).and_then(Yaml::as_sequence).unwrap();
            let commitments = points(sequence("commitments"));
            let commitment_indices: Vec<usize> = sequence("commitment_indices")
                .iter()
                .map(|item| usize::try_from(item.as_u64().unwrap()).unwrap())
                .collect();
            let cell_indices: Vec<CellIndex> = sequence("cell_indices")
                .iter()
                .map(|item| CellIndex::new(item.as_u64().unwrap()).unwrap())
                .collect();

            // Each coset is a list of 64 field elements, joined then decoded as a cell.
            let cells: Vec<Cell> = sequence("cosets_evals")
                .iter()
                .map(|evaluations| {
                    let bytes: Vec<u8> = evaluations
                        .as_sequence()
                        .unwrap()
                        .iter()
                        .flat_map(|item| item.as_hex_bytes().unwrap())
                        .collect();
                    Cell::from_bytes(&bytes).unwrap()
                })
                .collect();
            let proofs = points(sequence("proofs"));

            // The vectors give the distinct list and the indices directly, so the batch is built as is.
            let first_cells = (0..commitments.len())
                .map(|distinct| {
                    commitment_indices
                        .iter()
                        .position(|index| *index == distinct)
                        .unwrap()
                })
                .collect();
            let batch = CellBatch {
                commitments: commitments.iter().collect(),
                first_cells,
                commitment_indices,
                cell_indices: &cell_indices,
                cells: &cells,
                proofs: &proofs,
            };
            let expected = case.get("output").unwrap().as_hex_array().unwrap();
            assert_eq!(batch.challenge().to_bytes_be(), expected);
        }
    }

    #[test]
    fn repeated_commitments_share_one_weight() {
        // Fixture state: commitments [A, B, A] over three zero cells, with weights r^k = 1, 2, 4.
        let a = Bytes48([1; 48]);
        let b = Bytes48([2; 48]);
        let commitments = [a, b, a];
        let indices = [0, 1, 2].map(|index| CellIndex::new(index).unwrap());
        let cells = vec![Cell::from_evaluations(&[Scalar::ZERO; FIELD_ELEMENTS_PER_CELL]); 3];
        let proofs = [a; 3];
        let batch = CellBatch::new(&commitments, &indices, &cells, &proofs).unwrap();

        // A collects 1 + 4 = 5 and B collects 2.
        assert_eq!(batch.commitments(), [&a, &b]);
        assert_eq!(batch.first_cells(), [0, 1]);
        let powers = [1, 2, 4].map(Scalar::from_u64);
        assert_eq!(
            batch.commitment_weights(&powers),
            [5, 2].map(Scalar::from_u64)
        );

        // Four proofs for three cells do not pair up.
        assert_eq!(
            CellBatch::new(&commitments, &indices, &cells, &[a; 4]).unwrap_err(),
            KzgError::CellBatchLengthMismatch {
                commitments: 3,
                cell_indices: 3,
                cells: 3,
                proofs: 4
            }
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4))]

        #[test]
        fn cell_batch_equals_individual_checks(
            seeds in vec(any::<u64>(), 1..3),
            rows in vec((0..CELLS_PER_EXT_BLOB as u64, any::<Index>(), any::<bool>()), 1..6),
        ) {
            let kzg = Kzg::mainnet();
            let blobs: Vec<Blob> = seeds.into_iter().map(blob_from_seed).collect();
            let commitments: Vec<Bytes48> = blobs.iter().map(|blob| kzg.blob_to_kzg_commitment(blob)).collect();
            let extended: Vec<_> = blobs.iter().map(|blob| kzg.compute_cells_and_kzg_proofs(blob)).collect();

            // Fixture state: each row picks a blob and a cell, and maybe swaps in a wrong proof.
            // Rows may repeat a commitment, which exercises deduplication.
            let mut row_commitments = Vec::new();
            let mut indices = Vec::new();
            let mut cells = Vec::new();
            let mut proofs = Vec::new();
            for (cell, blob, corrupt) in rows {
                let blob = blob.index(blobs.len());
                let position = cell as usize;
                row_commitments.push(commitments[blob]);
                indices.push(CellIndex::new(cell).unwrap());
                cells.push(extended[blob].0[position].clone());
                let proof = if corrupt { extended[blob].1[(position + 1) % CELLS_PER_EXT_BLOB] } else { extended[blob].1[position] };
                proofs.push(proof);
            }

            // The batch accepts exactly when every single-cell batch accepts.
            let individual = (0..indices.len()).all(|row| {
                kzg.verify_cell_kzg_proof_batch(
                    &row_commitments[row..=row],
                    &indices[row..=row],
                    &cells[row..=row],
                    &proofs[row..=row],
                ) == Ok(true)
            });
            prop_assert_eq!(kzg.verify_cell_kzg_proof_batch(&row_commitments, &indices, &cells, &proofs), Ok(individual));
        }
    }
}
