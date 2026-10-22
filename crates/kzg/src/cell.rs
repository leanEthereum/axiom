//! Cells: 64 evaluations of a blob's polynomial over one coset of the extended domain.
//!
//! # Overview
//!
//! EIP-7594 extends a blob to 8192 evaluations, a Reed-Solomon code of rate one half.
//! The extended evaluations sit in bit-reversal order and split into 128 cells of 64.
//!
//! Write w for the root of unity of order 8192 and g = w^128 for the one of order 64.
//! G_64 is the group of the 64 powers of g.
//! Position 64 k + j of the extended blob reverses 13 bits, which swaps the two index fields:
//!
//! ```text
//!     position   64 k + j      =  [ k : 7 bits ][ j : 6 bits ]
//!     reversed   rev_13(...)   =  [ rev_6(j) : 6 bits ][ rev_7(k) : 7 bits ]
//!                              =  128 rev_6(j) + rev_7(k)
//!
//!     point      w^{128 rev_6(j) + rev_7(k)}  =  h_k * g^{rev_6(j)}     with h_k = w^{rev_7(k)}
//! ```
//!
//! So cell k holds the evaluations over the coset h_k G_64, itself in bit-reversal order.
//! Every coset is a shift of the same subgroup G_64, which makes cells interchangeable for FFTs.
//!
//! ```text
//!     cell 0     cell 1     ...   cell 63    |  cell 64   ...   cell 127
//!     h = 1      h = w^64         h = w^126  |  h = w           h = w^127
//!     <-------- the original blob -------->  |  <---- the Reed-Solomon extension ---->
//! ```
//!
//! The first 64 cells carry the blob itself, because rev_13 of an index below 4096 is even.

use axiom_bls12_381::{SCALAR_BYTES, Scalar};

use crate::{
    BYTES_PER_CELL, Bytes32, Bytes48, CELLS_PER_EXT_BLOB, FIELD_ELEMENTS_PER_CELL, KzgError,
};

/// All 128 cells of an extended blob with their proofs, both in cell order.
///
/// This is the pair that compute_cells_and_kzg_proofs returns in the Fulu spec.
pub type CellsAndProofs = (
    Box<[Cell; CELLS_PER_EXT_BLOB]>,
    Box<[Bytes48; CELLS_PER_EXT_BLOB]>,
);

/// A validated cell: 64 canonical field elements.
///
/// See Cell and cell_to_coset_evals in the Fulu polynomial commitments sampling spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell([Scalar; FIELD_ELEMENTS_PER_CELL]);

impl Cell {
    /// Decodes and validates the 2048 bytes of a cell.
    ///
    /// # Errors
    ///
    /// Fails when the length is wrong or any field element is not canonical.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KzgError> {
        if bytes.len() != BYTES_PER_CELL {
            return Err(KzgError::InvalidCellLength(bytes.len()));
        }
        // The length check above leaves exactly 64 chunks of 32 bytes, one per element.
        let (chunks, _) = bytes.as_chunks::<SCALAR_BYTES>();
        let mut evaluations = [Scalar::ZERO; FIELD_ELEMENTS_PER_CELL];
        for (index, (evaluation, chunk)) in evaluations.iter_mut().zip(chunks).enumerate() {
            *evaluation = Bytes32(*chunk)
                .to_scalar()
                .ok_or(KzgError::NonCanonicalCellElement { index })?;
        }
        Ok(Self(evaluations))
    }

    /// Encodes the cell back into its 2048 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.iter().flat_map(Scalar::to_bytes_be).collect()
    }

    /// Wraps evaluations that are canonical by construction.
    pub(crate) const fn from_evaluations(evaluations: &[Scalar; FIELD_ELEMENTS_PER_CELL]) -> Self {
        Self(*evaluations)
    }

    /// The evaluations over the cell's coset, in bit-reversal order.
    pub(crate) const fn evaluations(&self) -> &[Scalar; FIELD_ELEMENTS_PER_CELL] {
        &self.0
    }
}

/// The position of a cell in an extended blob, always below 128.
///
/// It is also the index of the data column that carries the cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CellIndex(u8);

impl CellIndex {
    /// Validates a cell index.
    ///
    /// # Errors
    ///
    /// Fails when the index is not below 128.
    pub const fn new(index: u64) -> Result<Self, KzgError> {
        // CELLS_PER_EXT_BLOB = 128 fits a byte, so the narrowing below is exact.
        if index >= CELLS_PER_EXT_BLOB as u64 {
            return Err(KzgError::CellIndexOutOfRange(index));
        }
        Ok(Self(index as u8))
    }

    /// The index as an integer.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0 as u64
    }

    /// The index as a position into arrays of cells.
    pub(crate) const fn position(self) -> usize {
        self.0 as usize
    }

    /// Every cell index of an extended blob, in ascending order.
    pub(crate) fn all() -> impl Iterator<Item = Self> {
        // CELLS_PER_EXT_BLOB = 128 fits a byte, so every position is a valid index.
        (0..CELLS_PER_EXT_BLOB as u8).map(Self)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn index_is_bounded_by_cell_count() {
        // 127 is the last cell and 128 is one past it.
        assert_eq!(CellIndex::new(127).map(CellIndex::get), Ok(127));
        assert_eq!(CellIndex::new(128), Err(KzgError::CellIndexOutOfRange(128)));
        // Large values are rejected rather than truncated to a byte.
        assert_eq!(
            CellIndex::new(256 + 3),
            Err(KzgError::CellIndexOutOfRange(259))
        );
    }

    #[test]
    fn cell_length_must_be_exact() {
        // 2049 bytes is one byte too many.
        assert_eq!(
            Cell::from_bytes(&[0; BYTES_PER_CELL + 1]),
            Err(KzgError::InvalidCellLength(2049))
        );
    }

    #[test]
    fn non_canonical_cell_element_is_named() {
        // Fixture state: element 7 is all 0xff bytes, far above the modulus.
        let mut bytes = vec![0; BYTES_PER_CELL];
        bytes[7 * 32..8 * 32].fill(0xff);
        assert_eq!(
            Cell::from_bytes(&bytes),
            Err(KzgError::NonCanonicalCellElement { index: 7 })
        );
    }

    #[test]
    fn cell_bytes_round_trip() {
        // Element 63 holds 0x0102, every other element zero.
        let mut bytes = vec![0; BYTES_PER_CELL];
        bytes[BYTES_PER_CELL - 2..].copy_from_slice(&[1, 2]);
        let cell = Cell::from_bytes(&bytes).unwrap();
        assert_eq!(cell.evaluations()[63], Scalar::from_u64(0x0102));
        assert_eq!(cell.to_bytes(), bytes);
    }

    /// Every cell index.
    pub(crate) fn all_indices() -> Vec<CellIndex> {
        (0..CELLS_PER_EXT_BLOB as u64)
            .map(|index| CellIndex::new(index).expect("index below 128"))
            .collect()
    }
}
