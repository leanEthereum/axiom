//! EIP-7594: erasure recovery of a blob's polynomial from any half of its cells.
//!
//! See recover_cells_and_kzg_proofs in `specs/fulu/polynomial-commitments-sampling.md`.

use std::mem;

use axiom_bls12_381::Scalar;

use super::cosets::Cosets;
use crate::{
    CELLS_PER_EXT_BLOB, Cell, CellIndex, FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL,
    FIELD_ELEMENTS_PER_EXT_BLOB, KzgError, fft::Domain,
};

/// The EIP-7594 erasure decoder: the coefficients behind any 64 of the 128 cells.
#[derive(Clone, Debug)]
pub(super) struct CellRecovery {
    /// The 8192-th roots of unity, the extended blob's evaluation domain.
    extended_domain: Domain,
    /// The per-cell coset constants.
    cosets: Cosets,
}

impl CellRecovery {
    /// Builds the decoder over the extended domain and its coset table.
    pub(super) const fn new(extended_domain: Domain, cosets: Cosets) -> Self {
        Self {
            extended_domain,
            cosets,
        }
    }

    /// Recovers the 4096 coefficients of the polynomial behind the cells.
    ///
    /// # Algorithm
    ///
    /// Let E be the extended evaluations with zeros at missing cells, and Z vanish on the missing points.
    /// The wanted polynomial P has degree below 4096 and agrees with E on every present point:
    ///
    /// ```text
    ///     E(x) Z(x) = P(x) Z(x)      at every one of the 8192 points
    /// ```
    ///
    /// P Z has degree below 8192, so an inverse FFT of the pointwise product E Z gives its coefficients.
    /// Dividing by Z over a coset, where Z has no root, then yields P.
    ///
    /// Z is cheap because each missing cell is a whole coset h G_64:
    ///
    /// ```text
    ///     prod_{x in h G_64} (X - x) = X^64 - h^64      so      Z(X) = z(X^64)
    /// ```
    ///
    /// Here z is the small polynomial whose roots are the h^64 of the missing cells.
    ///
    /// Reference: Buterin, "Reed-Solomon erasure code recovery in n log^2 n time with FFTs", ethresear.ch, 2018.
    ///
    /// # Errors
    ///
    /// Fails when the indices and cells differ in number, number fewer than 64 or more than 128, repeat, or descend.
    pub(super) fn recover(
        &self,
        cell_indices: &[CellIndex],
        cells: &[Cell],
    ) -> Result<Vec<Scalar>, KzgError> {
        // Phase 1: the spec's input checks, in its order.
        if cell_indices.len() != cells.len() {
            return Err(KzgError::RecoveryLengthMismatch {
                cell_indices: cell_indices.len(),
                cells: cells.len(),
            });
        }
        if !(CELLS_PER_EXT_BLOB / 2..=CELLS_PER_EXT_BLOB).contains(&cells.len()) {
            return Err(KzgError::InvalidCellCount(cells.len()));
        }
        let mut present = [false; CELLS_PER_EXT_BLOB];
        for index in cell_indices {
            if mem::replace(&mut present[index.position()], true) {
                return Err(KzgError::DuplicateCellIndex(index.get()));
            }
        }
        if let Some(pair) = cell_indices.windows(2).find(|pair| pair[0] > pair[1]) {
            return Err(KzgError::UnsortedCellIndices {
                previous: pair[0].get(),
                next: pair[1].get(),
            });
        }

        // Phase 2: the coefficients, recover_polynomialcoeff in the Fulu spec.
        Ok(self.coefficients(cell_indices, cells, &present))
    }

    /// Interpolates the coefficients from validated cells, recover_polynomialcoeff in the Fulu spec.
    fn coefficients(
        &self,
        cell_indices: &[CellIndex],
        cells: &[Cell],
        present: &[bool; CELLS_PER_EXT_BLOB],
    ) -> Vec<Scalar> {
        let domain = &self.extended_domain;

        // Phase 1: E in natural order, with zeros where cells are missing.
        //
        //     storage (bit-reversed)    [ cell 0 | cell 1 | 0 ... 0 | cell 3 | ... ]
        //     permute                   E(w^0), E(w^1), ..., E(w^8191)
        let mut extended = vec![Scalar::ZERO; FIELD_ELEMENTS_PER_EXT_BLOB];
        for (index, cell) in cell_indices.iter().zip(cells) {
            let start = index.position() * FIELD_ELEMENTS_PER_CELL;
            extended[start..start + FIELD_ELEMENTS_PER_CELL].copy_from_slice(cell.evaluations());
        }
        domain.bit_reversal().permute(&mut extended);

        // Phase 2: Z in coefficient form, and its evaluations over the domain.
        let vanishing = self.vanishing_polynomial(present);
        let mut vanishing_evaluations = vanishing.clone();
        domain.fft(&mut vanishing_evaluations);

        // Phase 3: coefficients of P Z, from the pointwise product E Z.
        for (value, z) in extended.iter_mut().zip(&vanishing_evaluations) {
            *value *= z;
        }
        domain.ifft(&mut extended);

        // Phase 4: divide by Z over the coset 7 * w^i, where Z never vanishes.
        // Its roots are roots of unity, and 7 generates the whole multiplicative group.
        let shift = Scalar::MULTIPLICATIVE_GENERATOR;
        let mut vanishing_on_coset = vanishing;
        domain.coset_fft(&mut extended, &shift);
        domain.coset_fft(&mut vanishing_on_coset, &shift);
        Scalar::batch_invert(&mut vanishing_on_coset);
        for (value, inverse) in extended.iter_mut().zip(&vanishing_on_coset) {
            *value *= inverse;
        }
        domain.coset_ifft(&mut extended, &shift);

        // Phase 5: keep the 4096 coefficients a blob can have, as the spec truncates.
        extended.truncate(FIELD_ELEMENTS_PER_BLOB);
        extended
    }

    /// The polynomial of degree at most 4096 vanishing on every missing cell, construct_vanishing_polynomial in the Fulu spec.
    ///
    /// ```text
    ///     z(Y) = prod_{k missing} (Y - h_k^64)        Z(X) = z(X^64)
    /// ```
    fn vanishing_polynomial(&self, present: &[bool; CELLS_PER_EXT_BLOB]) -> Vec<Scalar> {
        // Phase 1: multiply out z one linear factor at a time.
        //
        //     (c_0 + c_1 Y + ...)(Y - a) = -a c_0 + (c_0 - a c_1) Y + ...
        let mut small = vec![Scalar::ONE];
        for cell in CellIndex::all().filter(|cell| !present[cell.position()]) {
            let root = self.cosets.vanishing_constant(cell);
            small.push(Scalar::ZERO);
            for i in (0..small.len()).rev() {
                let lower = if i == 0 { Scalar::ZERO } else { small[i - 1] };
                small[i] = lower - small[i] * root;
            }
        }

        // Phase 2: substitute Y = X^64 by spreading the coefficients 64 apart.
        let mut vanishing = vec![Scalar::ZERO; FIELD_ELEMENTS_PER_EXT_BLOB];
        for (i, coefficient) in small.into_iter().enumerate() {
            vanishing[i * FIELD_ELEMENTS_PER_CELL] = coefficient;
        }
        vanishing
    }
}

#[cfg(test)]
mod tests {
    use proptest::{prelude::*, sample::subsequence};

    use super::*;
    use crate::{
        Kzg, bit_reversal::BitReversal, blob::tests::arb_blob, cell::tests::all_indices,
        fft::tests::horner,
    };

    /// Cell indices from integers known to be in range.
    fn indices(values: impl IntoIterator<Item = u64>) -> Vec<CellIndex> {
        values
            .into_iter()
            .map(|value| CellIndex::new(value).unwrap())
            .collect()
    }

    #[test]
    fn malformed_inputs_name_the_broken_rule() {
        let kzg = Kzg::mainnet();
        let zero = Cell::from_evaluations(&[Scalar::ZERO; FIELD_ELEMENTS_PER_CELL]);

        // 64 indices but 63 cells: the lists must pair up.
        let cells = vec![zero.clone(); 63];
        assert_eq!(
            kzg.recover_cells_and_kzg_proofs(&indices(0..64), &cells)
                .unwrap_err(),
            KzgError::RecoveryLengthMismatch {
                cell_indices: 64,
                cells: 63
            }
        );

        // 63 cells: one short of half.
        assert_eq!(
            kzg.recover_cells_and_kzg_proofs(&indices(0..63), &cells)
                .unwrap_err(),
            KzgError::InvalidCellCount(63)
        );

        // 64 cells with index 5 twice, at positions 5 and 63.
        let cells = vec![zero; 64];
        let duplicated = indices((0..63).chain([5]));
        assert_eq!(
            kzg.recover_cells_and_kzg_proofs(&duplicated, &cells)
                .unwrap_err(),
            KzgError::DuplicateCellIndex(5)
        );

        // 64 distinct indices with the first two swapped: [1, 0, 2, 3, ...].
        let swapped = indices([1, 0].into_iter().chain(2..64));
        assert_eq!(
            kzg.recover_cells_and_kzg_proofs(&swapped, &cells)
                .unwrap_err(),
            KzgError::UnsortedCellIndices {
                previous: 1,
                next: 0
            }
        );
    }

    #[test]
    fn vanishing_polynomial_vanishes_exactly_on_missing_cells() {
        // Fixture state: cells 0 and 77 missing, the other 126 present.
        let recovery = &Kzg::mainnet().recovery;
        let mut present = [true; CELLS_PER_EXT_BLOB];
        present[0] = false;
        present[77] = false;
        let vanishing = recovery.vanishing_polynomial(&present);

        // Degree 2 * 64 = 128, monic.
        assert_eq!(vanishing[128], Scalar::ONE);
        assert!(vanishing[129..].iter().all(Scalar::is_zero));

        // Zero on every point of cell 77, nonzero on a point of cell 1.
        //
        //     cell k, position j  ->  w^{128 rev_6(j) + rev_7(k)}
        let w = recovery.extended_domain.roots();
        for j in 0..FIELD_ELEMENTS_PER_CELL {
            let point = w[128 * BitReversal::new(6).index(j) + BitReversal::new(7).index(77)];
            assert!(horner(&vanishing, &point).is_zero());
        }
        assert!(!horner(&vanishing, &w[BitReversal::new(7).index(1)]).is_zero());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4))]

        #[test]
        fn recovery_from_any_half(blob in arb_blob(), kept in subsequence(all_indices(), 64..=128)) {
            let kzg = Kzg::mainnet();
            let (cells, proofs) = kzg.compute_cells_and_kzg_proofs(&blob);

            // Fixture state: a random ascending subset of at least 64 of the 128 cells.
            let available: Vec<Cell> = kept.iter().map(|index| cells[index.get() as usize].clone()).collect();

            // Recovery returns every cell and every proof of the original.
            let (recovered_cells, recovered_proofs) = kzg.recover_cells_and_kzg_proofs(&kept, &available).unwrap();
            prop_assert_eq!(recovered_cells, cells);
            prop_assert_eq!(recovered_proofs, proofs);
        }
    }
}
