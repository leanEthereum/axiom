//! The KZG context: the trusted setup and the precomputed domains every operation shares.
//!
//! The public operations live in focused files, one per spec section:
//!
//! - blob commitments and openings of EIP-4844,
//! - cell computation and batch verification of EIP-7594,
//! - erasure recovery of EIP-7594.

mod blob_proofs;
mod cell_proofs;
mod recovery;

use std::{fmt, sync::OnceLock};

use axiom_bls12_381::Scalar;

use crate::{
    Blob, FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL,
    fft::{Domain, bit_reverse_permute, reverse_bits},
    fk20::Fk20,
    setup::TrustedSetup,
};

/// Base-two logarithm of the blob size, 4096 evaluations.
const LOG_BLOB: u32 = 12;

/// Base-two logarithm of the extended blob size, 8192 evaluations.
const LOG_EXT_BLOB: u32 = 13;

/// Base-two logarithm of the cell size, 64 evaluations.
const LOG_CELL: u32 = 6;

/// Base-two logarithm of the number of cells, 128 per extended blob.
const LOG_CELLS: u32 = 7;

/// The KZG commitment scheme over the mainnet trusted setup.
///
/// Building it decodes the setup and precomputes roots of unity, so one shared instance serves all calls.
/// The FK20 tables for cell proofs are built on first use, since verifiers never need them.
pub struct Kzg {
    /// The decoded trusted setup.
    pub(crate) setup: TrustedSetup,
    /// The 4096-th roots of unity, the blob's evaluation domain.
    blob_domain: Domain,
    /// The blob domain in bit-reversal order, matching the order of blob evaluations.
    blob_roots_brp: Vec<Scalar>,
    /// The 8192-th roots of unity, the extended blob's evaluation domain.
    extended_domain: Domain,
    /// The 64-th roots of unity, the subgroup each cell's coset shifts.
    cell_domain: Domain,
    /// The 128-th roots of unity, one per cell.
    pub(crate) cell_count_domain: Domain,
    /// The FK20 setup transforms, built on the first proof computation.
    fk20: OnceLock<Fk20>,
}

impl Kzg {
    /// The context over the mainnet trusted setup of the KZG ceremony.
    ///
    /// The first call decodes the embedded setup: about 125 ms of work, spread over all cores.
    /// Later calls return the same instance.
    #[must_use]
    pub fn mainnet() -> &'static Self {
        static MAINNET: OnceLock<Kzg> = OnceLock::new();
        MAINNET.get_or_init(|| Self::new(TrustedSetup::mainnet()))
    }

    /// Precomputes the domains around a decoded setup.
    fn new(setup: TrustedSetup) -> Self {
        let blob_domain = Domain::new(LOG_BLOB);
        // The spec stores blob evaluations at the bit-reversed roots, so the roots follow suit.
        let mut blob_roots_brp = blob_domain.roots().to_vec();
        bit_reverse_permute(&mut blob_roots_brp);
        Self {
            setup,
            blob_domain,
            blob_roots_brp,
            extended_domain: Domain::new(LOG_EXT_BLOB),
            cell_domain: Domain::new(LOG_CELL),
            cell_count_domain: Domain::new(LOG_CELLS),
            fk20: OnceLock::new(),
        }
    }

    /// The FK20 tables, built on first use.
    pub(crate) fn fk20(&self) -> &Fk20 {
        self.fk20
            .get_or_init(|| Fk20::new(&self.setup.g1_monomial, &self.cell_count_domain))
    }

    /// The inverse h_k^{-1} of the shift of cell k's coset, coset_shift_for_cell in the Fulu spec.
    ///
    /// ```text
    ///     h_k = w^{rev_7(k)}        w of order 8192
    /// ```
    pub(crate) fn coset_shift_inverse(&self, cell: usize) -> Scalar {
        // w^{-i} sits at position i of the inverse root table.
        self.extended_domain.inverse_roots()[reverse_bits(cell, LOG_CELLS)]
    }

    /// The constant h_k^64 of the vanishing polynomial X^64 - h_k^64 of cell k's coset.
    ///
    /// ```text
    ///     h_k^64 = w^{64 rev_7(k)}        a root of unity of order 128
    /// ```
    pub(crate) fn coset_vanishing_constant(&self, cell: usize) -> Scalar {
        self.extended_domain.roots()[FIELD_ELEMENTS_PER_CELL * reverse_bits(cell, LOG_CELLS)]
    }

    /// Converts a blob from evaluations to its 4096 coefficients, polynomial_eval_to_coeff in the Fulu spec.
    fn blob_coefficients(&self, blob: &Blob) -> Vec<Scalar> {
        // Undo the storage order, then interpolate over the 4096-th roots of unity.
        let mut coefficients = blob.evaluations().to_vec();
        debug_assert_eq!(coefficients.len(), FIELD_ELEMENTS_PER_BLOB);
        bit_reverse_permute(&mut coefficients);
        self.blob_domain.ifft(&mut coefficients);
        coefficients
    }
}

impl fmt::Debug for Kzg {
    /// Omits the setup, whose 8257 points would flood any log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kzg")
            .field("fk20_ready", &self.fk20.get().is_some())
            .finish_non_exhaustive()
    }
}
