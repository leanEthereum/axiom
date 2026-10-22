//! EIP-7594: erasure recovery of all cells and proofs from any half of the cells.
//!
//! See recover_cells_and_kzg_proofs in `specs/fulu/polynomial-commitments-sampling.md`.

use std::mem;

use axiom_bls12_381::Scalar;

use super::{Kzg, blob_proofs::check_lengths};
use crate::{
    CELLS_PER_EXT_BLOB, Cell, CellIndex, CellsAndProofs, FIELD_ELEMENTS_PER_BLOB,
    FIELD_ELEMENTS_PER_CELL, FIELD_ELEMENTS_PER_EXT_BLOB, KzgError, fft::bit_reverse_permute,
};

impl Kzg {
    /// Recovers all 128 cells and their proofs from at least 64 distinct cells.
    ///
    /// Cell indices must be strictly ascending.
    /// The cells are not checked against any commitment, so callers verify them first.
    /// Cells off the code still recover to some codeword, the one the spec's truncation picks.
    ///
    /// See recover_cells_and_kzg_proofs in the Fulu spec.
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
    /// Fails when:
    ///
    /// - the indices and cells differ in number,
    /// - there are fewer than 64 or more than 128 cells,
    /// - an index repeats,
    /// - the indices are not ascending.
    pub fn recover_cells_and_kzg_proofs(
        &self,
        cell_indices: &[CellIndex],
        cells: &[Cell],
    ) -> Result<CellsAndProofs, KzgError> {
        // Phase 1: the spec's input checks, in its order.
        check_lengths(cell_indices.len(), &[cells.len()])?;
        if !(CELLS_PER_EXT_BLOB / 2..=CELLS_PER_EXT_BLOB).contains(&cells.len()) {
            return Err(KzgError::InvalidCellCount(cells.len()));
        }
        let mut present = [false; CELLS_PER_EXT_BLOB];
        for index in cell_indices {
            if mem::replace(&mut present[index.position()], true) {
                return Err(KzgError::DuplicateCellIndex(index.get()));
            }
        }
        if !cell_indices.is_sorted() {
            return Err(KzgError::UnsortedCellIndices);
        }

        // Phase 2: recover the coefficients, then recompute everything from them.
        let coefficients = self.recover_coefficients(cell_indices, cells, &present);
        Ok(self.cells_and_proofs(&coefficients))
    }

    /// Recovers the 4096 coefficients of the polynomial behind the cells, recover_polynomialcoeff in the Fulu spec.
    fn recover_coefficients(
        &self,
        cell_indices: &[CellIndex],
        cells: &[Cell],
        present: &[bool],
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
        bit_reverse_permute(&mut extended);

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
    fn vanishing_polynomial(&self, present: &[bool]) -> Vec<Scalar> {
        // Phase 1: multiply out z one linear factor at a time.
        //
        //     (c_0 + c_1 Y + ...)(Y - a) = -a c_0 + (c_0 - a c_1) Y + ...
        let mut small = vec![Scalar::ONE];
        for cell in (0..CELLS_PER_EXT_BLOB).filter(|cell| !present[*cell]) {
            let root = self.coset_vanishing_constant(cell);
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
    use super::*;
    use crate::fft::{reverse_bits, tests::horner};

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
            KzgError::LengthMismatch {
                expected: 64,
                actual: 63
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
            KzgError::UnsortedCellIndices
        );
    }

    #[test]
    fn vanishing_polynomial_vanishes_exactly_on_missing_cells() {
        // Fixture state: cells 0 and 77 missing, the other 126 present.
        let kzg = Kzg::mainnet();
        let mut present = [true; CELLS_PER_EXT_BLOB];
        present[0] = false;
        present[77] = false;
        let vanishing = kzg.vanishing_polynomial(&present);

        // Degree 2 * 64 = 128, monic.
        assert_eq!(vanishing[128], Scalar::ONE);
        assert!(vanishing[129..].iter().all(Scalar::is_zero));

        // Zero on every point of cell 77, nonzero on a point of cell 1.
        //
        //     cell k, position j  ->  w^{128 rev_6(j) + rev_7(k)}
        let w = kzg.extended_domain.roots();
        for j in 0..FIELD_ELEMENTS_PER_CELL {
            let point = w[128 * reverse_bits(j, 6) + reverse_bits(77, 7)];
            assert!(horner(&vanishing, &point).is_zero());
        }
        assert!(!horner(&vanishing, &w[reverse_bits(1, 7)]).is_zero());
    }
}
