//! EIP-7594: batch verification of any set of cells against their commitments.
//!
//! See verify_cell_kzg_proof_batch in `specs/fulu/polynomial-commitments-sampling.md`.

use axiom_bls12_381::{G1Affine, G1Projective, G2Affine, Gt, Scalar};

use super::{cell_batch::CellBatch, cosets::Cosets};
use crate::{
    Bytes48, CellIndex, FIELD_ELEMENTS_PER_CELL, KzgError, basis::Basis, fft::Domain,
    parallel::Threads, powers::Powers,
};

/// The EIP-7594 cell verifier: one pairing check for any number of cells.
#[derive(Clone, Debug)]
pub(super) struct CellVerifier {
    /// The first 64 powers [s^i] in G1, enough to commit any cell's interpolant.
    monomial: Basis,
    /// The power [s^64]_2, which pairs against the vanishing polynomial of every coset.
    s64_g2: G2Affine,
    /// The 64-th roots of unity, the subgroup each cell's coset shifts.
    cell_domain: Domain,
    /// The per-cell coset constants.
    cosets: Cosets,
}

impl CellVerifier {
    /// Builds the verifier from its setup points and the coset table.
    pub(super) fn new(monomial: Basis, s64_g2: G2Affine, cosets: Cosets) -> Self {
        Self {
            monomial,
            s64_g2,
            cell_domain: Domain::new(FIELD_ELEMENTS_PER_CELL.trailing_zeros()),
            cosets,
        }
    }

    /// Checks every cell against its commitment, verify_cell_kzg_proof_batch in the Fulu spec.
    ///
    /// # Algorithm
    ///
    /// Cell k with commitment C_k, coset h_k G_64, evaluations e_k, and proof pi_k claims:
    ///
    /// ```text
    ///     f_k(X) - I_k(X) = q_k(X) (X^64 - h_k^64)        pi_k = [q_k(s)]
    /// ```
    ///
    /// Here I_k interpolates e_k over the coset.
    /// In the exponent, that reads C_k - [I_k(s)] + h_k^64 pi_k = s^64 pi_k.
    /// Weighting cell k by r^k and summing gives the universal verification equation:
    ///
    /// ```text
    ///     e( sum_k r^k pi_k , [s^64]_2 ) = e( RLC - RLI + RLP , [1]_2 )
    ///     RLC = sum_i w_i C_i
    ///     RLI = [sum_k r^k I_k(s)]
    ///     RLP = sum_k r^k h_k^64 pi_k
    /// ```
    ///
    /// The weight w_i of a distinct commitment sums r^k over its cells.
    /// The interpolants of cells in one column share a coset, so they aggregate before one inverse FFT.
    ///
    /// Reference: "A universal verification equation for data availability sampling", ethresear.ch, 2022.
    pub(super) fn verify(&self, batch: &CellBatch<'_>) -> Result<bool, KzgError> {
        // Phase 1: validate every point, commitments first, as the spec does.
        // Each decoding runs a subgroup check of about 40 microseconds, worth spreading over cores.
        // An empty batch has nothing left to check: every sum below would be the identity.
        // Each point travels with its input position, so a failure names the entry at fault.
        let threads = Threads::available();
        let commitments: Vec<(usize, &Bytes48)> = batch
            .first_cells()
            .iter()
            .copied()
            .zip(batch.commitments().iter().copied())
            .collect();
        let commitment_points: Result<Vec<G1Affine>, KzgError> =
            threads.map(&commitments, |(index, bytes)| bytes.to_commitment(*index));
        let commitment_points = commitment_points?;
        let proofs: Vec<(usize, &Bytes48)> = batch.proofs().iter().enumerate().collect();
        let proof_points: Result<Vec<G1Affine>, KzgError> =
            threads.map(&proofs, |(index, bytes)| bytes.to_proof(*index));
        let proof_points = proof_points?;
        if batch.len() == 0 {
            return Ok(true);
        }

        // Phase 2: the challenge r binds every input, then its powers weight the cells.
        let r_powers: Vec<Scalar> = Powers::new(batch.challenge()).take(batch.len()).collect();

        // Phase 3: the weights of the three MSMs.
        //
        //     LL  : r^k           on proofs
        //     RLC : w_i           on distinct commitments, w_i = sum of r^k over the cells of i
        //     RLP : r^k h_k^64    on proofs
        let weights = batch.commitment_weights(&r_powers);
        let proof_weights: Vec<Scalar> = batch
            .cell_indices()
            .iter()
            .zip(&r_powers)
            .map(|(index, power)| self.cosets.vanishing_constant(*index) * power)
            .collect();

        // Phase 4: the four group elements, the larger MSMs on separate threads.
        // RLI = [sum_k r^k I_k(s)] comes from aggregated columns.
        let ((ll, rlp), (rlc, rli)) = threads.join(
            || {
                threads.join(
                    || G1Projective::multi_exp(&proof_points, &r_powers),
                    || G1Projective::multi_exp(&proof_points, &proof_weights),
                )
            },
            || {
                (
                    G1Projective::multi_exp(&commitment_points, &weights),
                    self.commit_aggregated_interpolant(batch, &r_powers),
                )
            },
        );

        // Phase 5: one product of two pairings, with RL = RLC - RLI + RLP.
        //
        //     e(LL, [s^64]_2) * e(-RL, [1]_2) = 1   <=>   e(LL, [s^64]_2) = e(RL, [1]_2)
        let rl = rlc - rli + rlp;
        Ok(Gt::multi_pairing(&[
            (G1Affine::from(ll), self.s64_g2),
            (G1Affine::from(-rl), G2Affine::GENERATOR),
        ])
        .is_identity())
    }

    /// Commits to sum_k r^k I_k, the weighted interpolants of all cells.
    ///
    /// # Algorithm
    ///
    /// Cells of one column share the coset h G_64, so their weighted sum has one interpolant.
    /// That interpolant comes from a 64-point inverse FFT over G_64, then a rescaling:
    ///
    /// ```text
    ///     evaluations e_j = I(h g^{rev_6(j)})       bit-reversal order, as stored
    ///     permute, inverse FFT                      coefficients c_m of I(h X)
    ///     a_m = c_m h^{-m}                          coefficients of I(X)
    /// ```
    fn commit_aggregated_interpolant(
        &self,
        batch: &CellBatch<'_>,
        r_powers: &[Scalar],
    ) -> G1Projective {
        // Phase 1: fold the weighted cells of each column together.
        let mut columns = batch.weighted_columns(r_powers);

        // Phase 2: interpolate each used column and add the unshifted coefficients.
        let mut interpolant = [Scalar::ZERO; FIELD_ELEMENTS_PER_CELL];
        for (column, index) in columns.iter_mut().zip(CellIndex::all()) {
            let Some(values) = column else {
                continue;
            };
            // Stored order is bit-reversed within the coset, the transform wants natural order.
            self.cell_domain.bit_reversal().permute(values);
            self.cell_domain.ifft(values);

            // Undo the shift: coefficient m of I(h X) is a_m h^m.
            let shift_powers = Powers::new(self.cosets.shift_inverse(index));
            for ((sum, coefficient), power) in
                interpolant.iter_mut().zip(values.iter()).zip(shift_powers)
            {
                *sum += coefficient * &power;
            }
        }

        // Phase 3: commit with the first 64 powers of s.
        self.monomial.commit(&interpolant)
    }
}

#[cfg(test)]
mod tests {
    use axiom_bls12_381::{G1Projective, PointDecodeError, Scalar};

    use crate::{Bytes48, Cell, CellIndex, FIELD_ELEMENTS_PER_CELL, Kzg, KzgError};

    #[test]
    fn invalid_commitment_is_named_by_its_first_cell() {
        // Fixture state: three zero cells, the identity as every proof.
        let identity = Bytes48::from_point(&G1Projective::IDENTITY);
        let cells = vec![Cell::from_evaluations(&[Scalar::ZERO; FIELD_ELEMENTS_PER_CELL]); 3];
        let indices = [0, 1, 2].map(|index| CellIndex::new(index).unwrap());

        // Mutation: the infinity flags over a stray payload bit, named by cells 1 and 2.
        let mut stray = identity.0;
        stray[47] = 1;
        let bad = Bytes48(stray);
        let commitments = [identity, bad, bad];

        // The repeated commitment is decoded once and reported at cell 1, where it first appears.
        assert_eq!(
            Kzg::mainnet().verify_cell_kzg_proof_batch(
                &commitments,
                &indices,
                &cells,
                &[identity; 3]
            ),
            Err(KzgError::InvalidCommitment {
                index: 1,
                source: PointDecodeError::InvalidInfinityEncoding
            })
        );
    }
}
