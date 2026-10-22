//! KZG polynomial commitments for EIP-4844 blobs and EIP-7594 cells.
//!
//! # Overview
//!
//! A blob is a polynomial f of degree below 4096, given by its evaluations.
//! A commitment is the single G1 point [f(s)], for a secret s of the trusted setup.
//! An opening at z proves f(z) = y with the quotient q(X) = (f(X) - y) / (X - z):
//!
//! ```text
//!     e([f(s)] - [y], [1]_2)  =  e([q(s)], [s - z]_2)
//! ```
//!
//! The quotient exists exactly when f(z) = y, and s is unknown, so the check is binding.
//! The scheme is named after Kate, Zaverucha, and Goldberg, who introduced it.
//!
//! EIP-4844 opens a blob at a Fiat-Shamir challenge, to tie the blob to its commitment.
//! EIP-7594 extends each blob to 8192 evaluations and opens 64 of them at a time, one cell each.
//! Any 64 of the 128 cells recover the rest, so peers sample cells instead of downloading blobs.
//!
//! The crate implements, method for method:
//!
//! - `specs/deneb/polynomial-commitments.md` of the consensus specs,
//! - `specs/fulu/polynomial-commitments-sampling.md` of the consensus specs.
//!
//! Every input is public, so no operation here needs constant time.
//!
//! References:
//!
//! - Kate, Zaverucha, Goldberg, ASIACRYPT 2010:
//!   "Constant-Size Commitments to Polynomials and Their Applications".
//! - Feist, Khovratovich, "Fast amortized KZG proofs", eprint 2023/033, for all cell proofs at once.
//! - EIP-4844, shard blob transactions, and EIP-7594, peer data availability sampling.

mod basis;
mod bit_reversal;
mod blob;
mod bytes;
mod cell;
mod error;
mod fft;
mod kzg;
mod parallel;
mod powers;
mod setup;
#[cfg(test)]
mod test_vectors;
mod transcript;

pub use blob::Blob;
pub use bytes::{Bytes32, Bytes48};
pub use cell::{Cell, CellIndex, CellsAndProofs};
pub use error::KzgError;
pub use kzg::Kzg;

/// Number of bytes of a field element, BYTES_PER_FIELD_ELEMENT in the Deneb spec.
///
/// Scalars are below r < 2^255, so 32 bytes hold any of them.
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;

/// Number of field elements in a blob, FIELD_ELEMENTS_PER_BLOB in the Deneb spec.
///
/// A power of two, so the evaluation domain is a group of roots of unity.
pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;

/// Number of bytes in a blob, BYTES_PER_BLOB in the Deneb spec.
pub const BYTES_PER_BLOB: usize = BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB;

/// Number of bytes in a commitment, a compressed G1 point.
pub const BYTES_PER_COMMITMENT: usize = 48;

/// Number of bytes in a proof, a compressed G1 point.
pub const BYTES_PER_PROOF: usize = 48;

/// Number of field elements in an extended blob, FIELD_ELEMENTS_PER_EXT_BLOB in the Fulu spec.
///
/// The Reed-Solomon extension doubles the blob, so any half recovers the whole.
pub const FIELD_ELEMENTS_PER_EXT_BLOB: usize = 2 * FIELD_ELEMENTS_PER_BLOB;

/// Number of field elements in a cell, FIELD_ELEMENTS_PER_CELL in the Fulu spec.
///
/// It must divide the extended blob and stay below the 65 G2 points of the setup.
pub const FIELD_ELEMENTS_PER_CELL: usize = 64;

/// Number of bytes in a cell, BYTES_PER_CELL in the Fulu spec.
pub const BYTES_PER_CELL: usize = BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_CELL;

/// Number of cells in an extended blob, CELLS_PER_EXT_BLOB in the Fulu spec.
pub const CELLS_PER_EXT_BLOB: usize = FIELD_ELEMENTS_PER_EXT_BLOB / FIELD_ELEMENTS_PER_CELL;
