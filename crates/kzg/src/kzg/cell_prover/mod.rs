//! EIP-7594: the cells of an extended blob and the proofs of all of them.
//!
//! See compute_cells_and_kzg_proofs in `specs/fulu/polynomial-commitments-sampling.md`.

mod fk20;

use std::sync::OnceLock;

use axiom_bls12_381::{G1Projective, Scalar};

use self::fk20::Fk20;
use crate::{
    Blob, Bytes48, CELLS_PER_EXT_BLOB, Cell, CellsAndProofs, FIELD_ELEMENTS_PER_BLOB,
    FIELD_ELEMENTS_PER_CELL, FIELD_ELEMENTS_PER_EXT_BLOB, basis::Basis, fft::Domain,
};

/// The EIP-7594 cell prover: the Reed-Solomon extension, and FK20 for the proofs.
///
/// The FK20 tables are built on first use, since verifiers never need them.
#[derive(Debug)]
pub(super) struct CellProver {
    /// The powers [s^i] in G1, which the FK20 tables transform.
    monomial: Basis,
    /// The 4096-th roots of unity, the blob's evaluation domain.
    blob_domain: Domain,
    /// The 8192-th roots of unity, the extended blob's evaluation domain.
    extended_domain: Domain,
    /// The FK20 setup transforms, built on the first proof computation.
    fk20: OnceLock<Fk20>,
}

impl CellProver {
    /// Builds the prover around the monomial basis and the two evaluation domains.
    pub(super) const fn new(monomial: Basis, blob_domain: Domain, extended_domain: Domain) -> Self {
        Self {
            monomial,
            blob_domain,
            extended_domain,
            fk20: OnceLock::new(),
        }
    }

    /// Whether the FK20 tables exist yet.
    pub(super) fn is_ready(&self) -> bool {
        self.fk20.get().is_some()
    }

    /// Extends a blob and cuts it into cells, compute_cells in the Fulu spec.
    pub(super) fn compute_cells(&self, blob: &Blob) -> Box<[Cell; CELLS_PER_EXT_BLOB]> {
        self.cells(&self.coefficients(blob))
    }

    /// Computes the cells of a blob and the proof of each, compute_cells_and_kzg_proofs in the Fulu spec.
    pub(super) fn compute_cells_and_kzg_proofs(&self, blob: &Blob) -> CellsAndProofs {
        self.cells_and_proofs(&self.coefficients(blob))
    }

    /// Computes cells and proofs from the coefficients of a polynomial of degree below 4096.
    pub(super) fn cells_and_proofs(&self, coefficients: &[Scalar]) -> CellsAndProofs {
        let cells = self.cells(coefficients);
        // FK20 returns proofs in cell order, as projective points.
        // One batch normalization shares a single field inversion among all 128.
        let proofs = self.fk20().cell_proofs(coefficients);
        let compressed: Box<[Bytes48]> = G1Projective::batch_normalize(&proofs)
            .iter()
            .map(|point| Bytes48(point.to_compressed()))
            .collect();
        // Invariant: FK20 returns exactly one proof per cell.
        let Ok(compressed) = compressed.try_into() else {
            unreachable!("FK20 computes 128 proofs");
        };
        (cells, compressed)
    }

    /// The FK20 tables, built on first use.
    fn fk20(&self) -> &Fk20 {
        self.fk20.get_or_init(|| Fk20::new(&self.monomial))
    }

    /// Converts a blob from evaluations to its 4096 coefficients, polynomial_eval_to_coeff in the Fulu spec.
    fn coefficients(&self, blob: &Blob) -> Vec<Scalar> {
        // Undo the storage order, then interpolate over the 4096-th roots of unity.
        let mut coefficients = blob.evaluations().to_vec();
        debug_assert_eq!(coefficients.len(), FIELD_ELEMENTS_PER_BLOB);
        self.blob_domain.bit_reversal().permute(&mut coefficients);
        self.blob_domain.ifft(&mut coefficients);
        coefficients
    }

    /// Evaluates a polynomial over the extended domain and cuts the result into cells.
    fn cells(&self, coefficients: &[Scalar]) -> Box<[Cell; CELLS_PER_EXT_BLOB]> {
        // Zero-pad to 8192 coefficients, evaluate in natural order, then store bit-reversed.
        let mut extended = coefficients.to_vec();
        extended.resize(FIELD_ELEMENTS_PER_EXT_BLOB, Scalar::ZERO);
        self.extended_domain.fft(&mut extended);
        self.extended_domain.bit_reversal().permute(&mut extended);

        // Consecutive runs of 64 are the cells, each a coset in bit-reversal order.
        let (chunks, _) = extended.as_chunks::<FIELD_ELEMENTS_PER_CELL>();
        let cells: Box<[Cell]> = chunks.iter().map(Cell::from_evaluations).collect();
        // Invariant: 8192 evaluations cut into exactly 128 runs of 64.
        let Ok(cells) = cells.try_into() else {
            unreachable!("an extended blob holds 128 cells");
        };
        cells
    }
}

#[cfg(test)]
mod tests {
    use proptest::{prelude::*, sample::subsequence};

    use super::*;
    use crate::{CellIndex, Kzg, blob::tests::arb_blob, cell::tests::all_indices};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4))]

        #[test]
        fn cells_extend_the_blob_and_verify(blob in arb_blob(), picked in subsequence(all_indices(), 1..12)) {
            let kzg = Kzg::mainnet();
            let commitment = kzg.blob_to_kzg_commitment(&blob);
            let (cells, proofs) = kzg.compute_cells_and_kzg_proofs(&blob);

            // The cells alone agree with the cells computed alongside proofs.
            prop_assert_eq!(&kzg.compute_cells(&blob), &cells);

            // Systematic code: the first 64 cells, concatenated, are the blob itself.
            let prefix: Vec<u8> = cells[..CELLS_PER_EXT_BLOB / 2].iter().flat_map(Cell::to_bytes).collect();
            prop_assert_eq!(prefix, blob.to_bytes());

            // Completeness: any subset of cells verifies in one batch.
            let chosen: Vec<Cell> = picked.iter().map(|index| cells[index.get() as usize].clone()).collect();
            let chosen_proofs: Vec<Bytes48> = picked.iter().map(|index| proofs[index.get() as usize]).collect();
            let commitments = vec![commitment; picked.len()];
            prop_assert_eq!(kzg.verify_cell_kzg_proof_batch(&commitments, &picked, &chosen, &chosen_proofs), Ok(true));

            // Mutation: the first chosen cell claims to sit at the next position.
            //
            //     cell k evaluated on coset k+1 is not the blob there, so the batch fails.
            let mut shifted = picked.clone();
            shifted[0] = CellIndex::new((picked[0].get() + 1) % CELLS_PER_EXT_BLOB as u64).unwrap();
            prop_assert_eq!(kzg.verify_cell_kzg_proof_batch(&commitments, &shifted, &chosen, &chosen_proofs), Ok(false));
        }
    }
}
