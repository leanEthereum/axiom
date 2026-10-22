//! EIP-7594: cells of the extended blob, their proofs, and batch verification of any cell set.
//!
//! See `specs/fulu/polynomial-commitments-sampling.md` of the consensus specs.

use std::collections::HashMap;

use axiom_bls12_381::{G1Affine, G1Projective, G2Affine, Gt, Scalar};

use super::{
    Kzg,
    blob_proofs::{check_lengths, powers},
};
use crate::{
    Blob, Bytes48, CELLS_PER_EXT_BLOB, Cell, CellIndex, CellsAndProofs, FIELD_ELEMENTS_PER_CELL,
    FIELD_ELEMENTS_PER_EXT_BLOB, KzgError, bytes::into_boxed_array, fft::bit_reverse_permute,
    parallel, transcript::cell_batch_challenge,
};

impl Kzg {
    /// Extends a blob to 8192 evaluations and cuts them into 128 cells.
    ///
    /// See compute_cells in the Fulu spec.
    #[must_use]
    pub fn compute_cells(&self, blob: &Blob) -> Box<[Cell; CELLS_PER_EXT_BLOB]> {
        self.cells(&self.blob_coefficients(blob))
    }

    /// Computes the 128 cells of a blob and the proof of each.
    ///
    /// The spec opens each cell separately, in quadratic time.
    /// FK20 computes all 128 proofs with FFTs and 128 MSMs of 64 points instead.
    ///
    /// See compute_cells_and_kzg_proofs in the Fulu spec.
    #[must_use]
    pub fn compute_cells_and_kzg_proofs(&self, blob: &Blob) -> CellsAndProofs {
        self.cells_and_proofs(&self.blob_coefficients(blob))
    }

    /// Checks that every cell matches its commitment at its position, with one pairing check.
    ///
    /// The lists pair up entry by entry, and commitments may repeat.
    /// An empty batch is valid.
    ///
    /// See verify_cell_kzg_proof_batch in the Fulu spec.
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
    ///     e( sum_k r^k pi_k , [s^64]_2 )
    ///         = e( sum_i w_i C_i  -  [sum_k r^k I_k(s)]  +  sum_k r^k h_k^64 pi_k , [1]_2 )
    ///             \_____ RLC ___/    \______ RLI ______/    \_______ RLP _______/
    /// ```
    ///
    /// The weight w_i of a distinct commitment sums r^k over its cells.
    /// The interpolants of cells in one column share a coset, so they aggregate before one inverse FFT.
    ///
    /// Reference: "A universal verification equation for data availability sampling", ethresear.ch, 2022.
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
        check_lengths(
            commitments.len(),
            &[cell_indices.len(), cells.len(), proofs.len()],
        )?;

        // Phase 1: deduplicate commitments by their bytes, keeping first appearances in order.
        //
        //     commitments          [A, B, A, C]
        //     unique               [A, B, C]
        //     commitment indices   [0, 1, 0, 2]
        let mut unique: Vec<&Bytes48> = Vec::new();
        let mut positions: HashMap<&Bytes48, usize> = HashMap::new();
        let commitment_indices: Vec<usize> = commitments
            .iter()
            .map(|commitment| {
                *positions.entry(commitment).or_insert_with(|| {
                    unique.push(commitment);
                    unique.len() - 1
                })
            })
            .collect();

        // Phase 2: validate every point, commitments first, as the spec does.
        // An empty batch has nothing left to check: every sum below would be the identity.
        let unique_points = decode_points(&unique, |bytes| bytes.to_commitment())?;
        let proof_refs: Vec<&Bytes48> = proofs.iter().collect();
        let proof_points = decode_points(&proof_refs, |bytes| bytes.to_proof())?;
        if cells.is_empty() {
            return Ok(true);
        }

        // Phase 3: the challenge r binds every input, then its powers weight the cells.
        let evaluations: Vec<&[Scalar]> = cells
            .iter()
            .map(|cell| cell.evaluations().as_slice())
            .collect();
        let r = cell_batch_challenge(
            &unique,
            &commitment_indices,
            cell_indices,
            &evaluations,
            proofs,
        );
        let r_powers = powers(&r, cells.len());

        // Phase 4: the weights of the three MSMs.
        //
        //     LL  : r^k           on proofs
        //     RLC : w_i           on distinct commitments, w_i = sum of r^k over the cells of i
        //     RLP : r^k h_k^64    on proofs
        let mut weights = vec![Scalar::ZERO; unique.len()];
        for (index, power) in commitment_indices.iter().zip(&r_powers) {
            weights[*index] += power;
        }
        let proof_weights: Vec<Scalar> = cell_indices
            .iter()
            .zip(&r_powers)
            .map(|(index, power)| self.coset_vanishing_constant(index.position()) * power)
            .collect();

        // Phase 5: the four group elements, the larger MSMs on separate threads.
        // RLI = [sum_k r^k I_k(s)] comes from aggregated columns.
        let ((ll, rlp), (rlc, rli)) = parallel::join(
            || {
                parallel::join(
                    || G1Projective::multi_exp(&proof_points, &r_powers),
                    || G1Projective::multi_exp(&proof_points, &proof_weights),
                )
            },
            || {
                (
                    G1Projective::multi_exp(&unique_points, &weights),
                    self.commit_aggregated_interpolant(cell_indices, cells, &r_powers),
                )
            },
        );

        // Phase 6: one product of two pairings, with RL = RLC - RLI + RLP.
        //
        //     e(LL, [s^64]_2) * e(-RL, [1]_2) = 1   <=>   e(LL, [s^64]_2) = e(RL, [1]_2)
        let rl = rlc - rli + rlp;
        Ok(Gt::multi_pairing(&[
            (
                G1Affine::from(ll),
                self.setup.g2_monomial[FIELD_ELEMENTS_PER_CELL],
            ),
            (G1Affine::from(-rl), G2Affine::GENERATOR),
        ])
        .is_identity())
    }

    /// Computes cells and proofs from the coefficients of a polynomial of degree below 4096.
    pub(crate) fn cells_and_proofs(&self, coefficients: &[Scalar]) -> CellsAndProofs {
        let cells = self.cells(coefficients);
        // FK20 returns proofs in cell order, as projective points.
        // One batch normalization shares a single field inversion among all 128.
        let proofs = self
            .fk20()
            .cell_proofs(coefficients, &self.cell_count_domain);
        let compressed = G1Projective::batch_normalize(&proofs)
            .iter()
            .map(|point| Bytes48(point.to_compressed()))
            .collect();
        (cells, into_boxed_array(compressed))
    }

    /// Evaluates a polynomial over the extended domain and cuts the result into cells.
    fn cells(&self, coefficients: &[Scalar]) -> Box<[Cell; CELLS_PER_EXT_BLOB]> {
        // Zero-pad to 8192 coefficients, evaluate in natural order, then store bit-reversed.
        let mut extended = coefficients.to_vec();
        extended.resize(FIELD_ELEMENTS_PER_EXT_BLOB, Scalar::ZERO);
        self.extended_domain.fft(&mut extended);
        bit_reverse_permute(&mut extended);

        // Consecutive runs of 64 are the cells, each a coset in bit-reversal order.
        let (chunks, _) = extended.as_chunks::<FIELD_ELEMENTS_PER_CELL>();
        into_boxed_array(chunks.iter().map(Cell::from_evaluations).collect())
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
        cell_indices: &[CellIndex],
        cells: &[Cell],
        r_powers: &[Scalar],
    ) -> G1Projective {
        // Phase 1: fold the weighted cells of each column together.
        let mut columns: Vec<Option<[Scalar; FIELD_ELEMENTS_PER_CELL]>> =
            vec![None; CELLS_PER_EXT_BLOB];
        for ((index, cell), power) in cell_indices.iter().zip(cells).zip(r_powers) {
            let column =
                columns[index.position()].get_or_insert([Scalar::ZERO; FIELD_ELEMENTS_PER_CELL]);
            for (sum, value) in column.iter_mut().zip(cell.evaluations()) {
                *sum += value * power;
            }
        }

        // Phase 2: interpolate each used column and add the unshifted coefficients.
        let mut interpolant = [Scalar::ZERO; FIELD_ELEMENTS_PER_CELL];
        for (column_index, column) in columns.iter_mut().enumerate() {
            let Some(values) = column else {
                continue;
            };
            // Stored order is bit-reversed within the coset, the transform wants natural order.
            bit_reverse_permute(values);
            self.cell_domain.ifft(values);

            // Undo the shift: coefficient m of I(h X) is a_m h^m.
            let shift_inverse = self.coset_shift_inverse(column_index);
            let mut power = Scalar::ONE;
            for (sum, coefficient) in interpolant.iter_mut().zip(values.iter()) {
                *sum += coefficient * &power;
                power *= shift_inverse;
            }
        }

        // Phase 3: commit with the first 64 powers of s.
        G1Projective::multi_exp(
            &self.setup.g1_monomial[..FIELD_ELEMENTS_PER_CELL],
            &interpolant,
        )
    }
}

/// Decodes points in parallel, failing on the first malformed one in input order.
fn decode_points(
    points: &[&Bytes48],
    decode: impl Fn(&Bytes48) -> Result<G1Affine, KzgError> + Sync,
) -> Result<Vec<G1Affine>, KzgError> {
    // Each decoding runs a subgroup check of about 40 microseconds, worth spreading over cores.
    parallel::map(points, |bytes| decode(bytes))
        .into_iter()
        .collect()
}
