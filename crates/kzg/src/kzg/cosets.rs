//! The 128 cosets of the extended domain, one per cell, with the constants each proof needs.

use axiom_bls12_381::Scalar;

use crate::{
    CELLS_PER_EXT_BLOB, CellIndex, FIELD_ELEMENTS_PER_CELL, bit_reversal::BitReversal, fft::Domain,
};

/// Per-cell constants of the coset h_k G_64 that cell k covers.
///
/// ```text
///     h_k = w^{rev_7(k)}        w of order 8192
/// ```
#[derive(Clone, Debug)]
pub(super) struct Cosets {
    /// The inverse shifts h_k^{-1}, by cell index.
    shift_inverses: [Scalar; CELLS_PER_EXT_BLOB],
    /// The constants h_k^64 of the coset vanishing polynomials X^64 - h_k^64, by cell index.
    vanishing_constants: [Scalar; CELLS_PER_EXT_BLOB],
}

impl Cosets {
    /// Reads the constants off the extended domain's root tables.
    pub(super) fn new(extended: &Domain) -> Self {
        let mut shift_inverses = [Scalar::ZERO; CELLS_PER_EXT_BLOB];
        let mut vanishing_constants = [Scalar::ZERO; CELLS_PER_EXT_BLOB];
        let order = BitReversal::of_length(CELLS_PER_EXT_BLOB);
        for (cell, (inverse, constant)) in shift_inverses
            .iter_mut()
            .zip(&mut vanishing_constants)
            .enumerate()
        {
            // w^{-i} sits at position i of the inverse root table.
            let exponent = order.index(cell);
            *inverse = extended.inverse_roots()[exponent];
            // h_k^64 = w^{64 rev_7(k)} is a root of unity of order 128.
            *constant = extended.roots()[FIELD_ELEMENTS_PER_CELL * exponent];
        }
        Self {
            shift_inverses,
            vanishing_constants,
        }
    }

    /// The inverse h_k^{-1} of the shift of cell k's coset, coset_shift_for_cell in the Fulu spec.
    pub(super) const fn shift_inverse(&self, cell: CellIndex) -> Scalar {
        self.shift_inverses[cell.position()]
    }

    /// The constant h_k^64 of the vanishing polynomial X^64 - h_k^64 of cell k's coset.
    pub(super) const fn vanishing_constant(&self, cell: CellIndex) -> Scalar {
        self.vanishing_constants[cell.position()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_the_coset_shift() {
        // Cell 1 has rev_7(1) = 64, so h_1 = w^64 and h_1^64 = w^4096 = -1.
        let domain = Domain::new(13);
        let cosets = Cosets::new(&domain);
        let cell = CellIndex::new(1).unwrap();
        let shift = domain.roots()[64];
        assert_eq!(cosets.shift_inverse(cell) * shift, Scalar::ONE);
        assert_eq!(cosets.vanishing_constant(cell), -Scalar::ONE);
    }
}
