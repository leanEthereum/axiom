//! The KZG context: one entry point over the four parts of the scheme.
//!
//! Each part owns the setup points and domains it needs, one per spec section:
//!
//! - the blob commitments and openings of EIP-4844,
//! - the cell prover of EIP-7594, with its FK20 tables,
//! - the cell verifier of EIP-7594,
//! - the erasure recovery of EIP-7594.

mod blob_scheme;
mod cell_batch;
mod cell_prover;
mod cell_verifier;
mod cosets;
mod opening;
mod recovery;

use std::{fmt, sync::OnceLock};

use axiom_bls12_381::{G1_COMPRESSED_BYTES, G2_COMPRESSED_BYTES};

use self::{
    blob_scheme::BlobScheme, cell_batch::CellBatch, cell_prover::CellProver,
    cell_verifier::CellVerifier, cosets::Cosets, recovery::CellRecovery,
};
use crate::{
    Blob, Bytes32, Bytes48, CELLS_PER_EXT_BLOB, Cell, CellIndex, CellsAndProofs,
    FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL, FIELD_ELEMENTS_PER_EXT_BLOB, KzgError,
    fft::Domain, setup::TrustedSetup,
};

/// The context the process trusts, set once.
static TRUSTED: OnceLock<Kzg> = OnceLock::new();

/// The KZG commitment scheme over a trusted setup, by default the mainnet one.
///
/// Building it decodes the setup and precomputes roots of unity, so one shared instance serves all calls.
/// The FK20 tables for cell proofs are built on first use, since verifiers never need them.
pub struct Kzg {
    /// The EIP-4844 prover and verifier.
    blobs: BlobScheme,
    /// The EIP-7594 cell prover.
    cell_prover: CellProver,
    /// The EIP-7594 cell verifier.
    cell_verifier: CellVerifier,
    /// The EIP-7594 erasure decoder.
    recovery: CellRecovery,
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

    /// The context over a trusted setup given as compressed points.
    ///
    /// Each basis lists its points in the order of the setup files.
    /// The Lagrange basis is in natural order.
    /// See `trusted_setup_4096.json` in the consensus specs.
    ///
    /// # Errors
    ///
    /// Fails when a basis has another number of points than the scheme needs.
    /// Fails when a point is not in its subgroup.
    pub fn from_trusted_setup(
        g1_monomial: &[[u8; G1_COMPRESSED_BYTES]],
        g1_lagrange: &[[u8; G1_COMPRESSED_BYTES]],
        g2_monomial: &[[u8; G2_COMPRESSED_BYTES]],
    ) -> Result<Self, KzgError> {
        TrustedSetup::from_compressed(g1_monomial, g1_lagrange, g2_monomial).map(Self::new)
    }

    /// Makes this context the one the process trusts, before any operation reads it.
    ///
    /// # Errors
    ///
    /// Fails when the process already trusts a context, which earlier operations may have used.
    pub fn trust(self) -> Result<&'static Self, KzgError> {
        TRUSTED
            .set(self)
            .map_err(|_| KzgError::SetupAlreadyTrusted)?;
        TRUSTED.get().ok_or(KzgError::SetupAlreadyTrusted)
    }

    /// The context the process trusts: one an operator installed, else the mainnet setup.
    ///
    /// A node reads its context here, so an operator's setup reaches every operation alike.
    #[must_use]
    pub fn trusted() -> &'static Self {
        TRUSTED.get_or_init(|| Self::new(TrustedSetup::mainnet()))
    }

    /// Hands each part its share of the setup and the domains it works over.
    fn new(setup: TrustedSetup) -> Self {
        let blob_domain = Domain::new(FIELD_ELEMENTS_PER_BLOB.trailing_zeros());
        let extended_domain = Domain::new(FIELD_ELEMENTS_PER_EXT_BLOB.trailing_zeros());
        let cosets = Cosets::new(&extended_domain);
        // Openings at one point pair against [s]_2, cell openings against [s^64]_2.
        let s_g2 = setup.g2_monomial[1];
        let s64_g2 = setup.g2_monomial[FIELD_ELEMENTS_PER_CELL];
        Self {
            blobs: BlobScheme::new(setup.g1_lagrange_brp, s_g2, &blob_domain),
            cell_verifier: CellVerifier::new(
                setup.g1_monomial.prefix(FIELD_ELEMENTS_PER_CELL),
                s64_g2,
                cosets.clone(),
            ),
            recovery: CellRecovery::new(extended_domain.clone(), cosets),
            cell_prover: CellProver::new(setup.g1_monomial, blob_domain, extended_domain),
        }
    }

    /// Commits to a blob: [f(s)] for the polynomial its evaluations define.
    ///
    /// The Lagrange basis turns the commitment into one MSM over the evaluations.
    ///
    /// ```text
    ///     [f(s)] = sum_i f(omega_i) [L_i(s)]
    /// ```
    ///
    /// See blob_to_kzg_commitment in the Deneb spec.
    #[must_use]
    pub fn blob_to_kzg_commitment(&self, blob: &Blob) -> Bytes48 {
        self.blobs.commit(blob)
    }

    /// Opens the blob's polynomial at z.
    ///
    /// See compute_kzg_proof in the Deneb spec.
    ///
    /// # Returns
    ///
    /// The proof and the evaluation y = f(z).
    ///
    /// # Errors
    ///
    /// Fails when z is not a canonical field element.
    pub fn compute_kzg_proof(
        &self,
        blob: &Blob,
        z: &Bytes32,
    ) -> Result<(Bytes48, Bytes32), KzgError> {
        self.blobs.compute_kzg_proof(blob, z)
    }

    /// Opens the blob at the Fiat-Shamir challenge derived from the blob and its commitment.
    ///
    /// The commitment is only validated, never checked against the blob.
    ///
    /// See compute_blob_kzg_proof in the Deneb spec.
    ///
    /// # Errors
    ///
    /// Fails when the commitment is not a point of G1.
    pub fn compute_blob_kzg_proof(
        &self,
        blob: &Blob,
        commitment: &Bytes48,
    ) -> Result<Bytes48, KzgError> {
        self.blobs.compute_blob_kzg_proof(blob, commitment)
    }

    /// Checks a proof that the committed polynomial takes the value y at z.
    ///
    /// See verify_kzg_proof in the Deneb spec.
    ///
    /// # Errors
    ///
    /// Fails when a point or a field element is malformed.
    /// A well-formed but wrong proof returns false.
    pub fn verify_kzg_proof(
        &self,
        commitment: &Bytes48,
        z: &Bytes32,
        y: &Bytes32,
        proof: &Bytes48,
    ) -> Result<bool, KzgError> {
        self.blobs.verify_kzg_proof(commitment, z, y, proof)
    }

    /// Checks a blob proof: the opening at the challenge matches the blob's own evaluation there.
    ///
    /// See verify_blob_kzg_proof in the Deneb spec.
    ///
    /// # Errors
    ///
    /// Fails when the commitment or the proof is not a point of G1.
    pub fn verify_blob_kzg_proof(
        &self,
        blob: &Blob,
        commitment: &Bytes48,
        proof: &Bytes48,
    ) -> Result<bool, KzgError> {
        self.blobs.verify_blob_kzg_proof(blob, commitment, proof)
    }

    /// Checks many blob proofs with one pairing check, true for an empty batch.
    ///
    /// See verify_blob_kzg_proof_batch in the Deneb spec.
    ///
    /// # Errors
    ///
    /// Fails when the lists differ in length or any point is malformed.
    pub fn verify_blob_kzg_proof_batch(
        &self,
        blobs: &[Blob],
        commitments: &[Bytes48],
        proofs: &[Bytes48],
    ) -> Result<bool, KzgError> {
        self.blobs
            .verify_blob_kzg_proof_batch(blobs, commitments, proofs)
    }

    /// Extends a blob to 8192 evaluations and cuts them into 128 cells.
    ///
    /// See compute_cells in the Fulu spec.
    #[must_use]
    pub fn compute_cells(&self, blob: &Blob) -> Box<[Cell; CELLS_PER_EXT_BLOB]> {
        self.cell_prover.compute_cells(blob)
    }

    /// Computes the 128 cells of a blob and the proof of each.
    ///
    /// The spec opens each cell separately, in quadratic time.
    /// FK20 computes all 128 proofs with FFTs and 128 MSMs of 64 points instead.
    ///
    /// See compute_cells_and_kzg_proofs in the Fulu spec.
    #[must_use]
    pub fn compute_cells_and_kzg_proofs(&self, blob: &Blob) -> CellsAndProofs {
        self.cell_prover.compute_cells_and_kzg_proofs(blob)
    }

    /// Checks that every cell matches its commitment at its position, with one pairing check.
    ///
    /// The lists pair up entry by entry, and commitments may repeat.
    /// An empty batch is valid.
    ///
    /// See verify_cell_kzg_proof_batch in the Fulu spec.
    ///
    /// # Errors
    ///
    /// Fails when the lists differ in length or any point is malformed.
    pub fn verify_cell_kzg_proof_batch(
        &self,
        commitments: &[Bytes48],
        cell_indices: &[CellIndex],
        cells: &[Cell],
        proofs: &[Bytes48],
    ) -> Result<bool, KzgError> {
        let batch = CellBatch::new(commitments, cell_indices, cells, proofs)?;
        self.cell_verifier.verify(&batch)
    }

    /// Recovers all 128 cells and their proofs from at least 64 distinct cells.
    ///
    /// Cell indices must be strictly ascending.
    /// The cells are not checked against any commitment, so callers verify them first.
    /// Cells off the code still recover to some codeword, the one the spec's truncation picks.
    ///
    /// See recover_cells_and_kzg_proofs in the Fulu spec.
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
        // Recovery yields the polynomial, from which the prover recomputes everything.
        let coefficients = self.recovery.recover(cell_indices, cells)?;
        Ok(self.cell_prover.cells_and_proofs(&coefficients))
    }
}

impl fmt::Debug for Kzg {
    /// Omits the setup, whose 8257 points would flood any log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kzg")
            .field("fk20_ready", &self.cell_prover.is_ready())
            .finish_non_exhaustive()
    }
}
