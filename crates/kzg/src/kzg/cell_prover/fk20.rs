//! All 128 cell proofs of a blob at once, by the Feist-Khovratovich method.
//!
//! # Overview
//!
//! The proof for cell k commits to the quotient of f by the vanishing polynomial of its coset.
//! The coset h_k G_64 has 64 points, so that polynomial is X^64 - a_k with a_k = h_k^64.
//!
//! Write f = sum_{t, u} f_{64 t + u} X^{64 t + u} with t < 64 and u < 64.
//! Dividing each X^{64 t} by X^64 - a leaves a geometric series in a:
//!
//! ```text
//!     quotient(s)  =  sum_{m=0}^{62} a^m h_m
//!     h_m          =  sum_{u=0}^{63} sum_{t=m+1}^{63} f_{64 t + u} [s^{u + 64 (t - 1 - m)}]
//! ```
//!
//! The 63 points h_m do not depend on the cell.
//! Every proof is then the G1 polynomial H(Y) = sum_m h_m Y^m at Y = a_k.
//! The a_k are exactly the 128-th roots of unity, so one G1 FFT of size 128 yields all proofs.
//!
//! Computing the h_m is a sum over u of 64 Toeplitz matrix-vector products:
//!
//! ```text
//!     [ h_0  ]       [ c_63  c_62  ...  c_1  ] [ x_0  ]        c_t = f_{64 t + u}
//!     [ h_1  ]       [  0    c_63  ...  c_2  ] [ x_1  ]        x_i = [s^{u + 64 (62 - i)}]
//!     [ ...  ]  +=   [            ...        ] [ ...  ]
//!     [ h_62 ]       [  0     0    ...  c_63 ] [ x_62 ]
//! ```
//!
//! Each embeds in a circulant product of size 128, which FFTs diagonalize.
//! The FFTs of the setup vectors are fixed and precomputed once.
//!
//! Reference: Feist and Khovratovich, "Fast amortized KZG proofs", eprint 2023/033, sections 2 and 3.
//! The index layout follows c-kzg-4844's fk20.c.

use axiom_bls12_381::{G1Affine, G1Projective, Scalar};

use crate::{
    CELLS_PER_EXT_BLOB, FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL, basis::Basis,
    fft::Domain, parallel::Threads,
};

/// Number of 64-coefficient blocks in a blob polynomial, CELLS_PER_BLOB in c-kzg-4844.
const BLOCKS: usize = FIELD_ELEMENTS_PER_BLOB / FIELD_ELEMENTS_PER_CELL;

/// Size of the circulant matrices that embed the Toeplitz products.
///
/// A Toeplitz matrix of size 63 embeds in a circulant of size 126, rounded up to a power of two.
const CIRCULANT: usize = 2 * BLOCKS;

/// The precomputed FFTs of the setup vectors, one per coefficient offset u.
#[derive(Clone, Debug)]
pub(super) struct Fk20 {
    /// The 128-th roots of unity, both the circulant size and the proof count.
    domain: Domain,
    /// Row j holds, for u = 0..63, entry j of the FFT of the u-th setup vector.
    ///
    /// The transposed layout makes each row the point list of one multi-scalar multiplication.
    rows: Vec<Vec<G1Affine>>,
}

impl Fk20 {
    /// Precomputes the setup FFTs from the monomial basis.
    ///
    /// # Performance
    ///
    /// 64 G1 FFTs of size 128, about 20000 scalar multiplications, spread over all cores.
    pub(super) fn new(g1_monomial: &Basis) -> Self {
        let domain = Domain::new(CIRCULANT.trailing_zeros());
        let offsets: Vec<usize> = (0..FIELD_ELEMENTS_PER_CELL).collect();

        // Phase 1: for each offset u, transform the vector x_u reversed against the Toeplitz rows.
        //
        //     x_u[i] = [s^{u + 64 (62 - i)}]    for i = 0..62
        //     x_u[i] = 0                        for i = 63..127  (circulant padding)
        let columns: Vec<Vec<G1Projective>> = Threads::available().map(&offsets, |&u| {
            let mut x = vec![G1Projective::IDENTITY; CIRCULANT];
            for (i, slot) in x.iter_mut().take(BLOCKS - 1).enumerate() {
                *slot = G1Projective::from(
                    g1_monomial.points()[u + FIELD_ELEMENTS_PER_CELL * (BLOCKS - 2 - i)],
                );
            }
            domain.fft(&mut x);
            x
        });

        // Phase 2: one batch normalization for all 8192 points, then transpose to rows.
        let flat: Vec<G1Projective> = columns.into_iter().flatten().collect();
        let affine = G1Projective::batch_normalize(&flat);
        let rows = (0..CIRCULANT)
            .map(|j| {
                (0..FIELD_ELEMENTS_PER_CELL)
                    .map(|u| affine[u * CIRCULANT + j])
                    .collect()
            })
            .collect();
        Self { domain, rows }
    }

    /// Computes the proofs of all 128 cells of a polynomial of degree below 4096.
    ///
    /// # Returns
    ///
    /// The proofs in cell order, as projective points.
    ///
    /// # Panics
    ///
    /// Panics when the polynomial does not have exactly 4096 coefficients.
    pub(super) fn cell_proofs(&self, coefficients: &[Scalar]) -> Vec<G1Projective> {
        assert_eq!(
            coefficients.len(),
            FIELD_ELEMENTS_PER_BLOB,
            "one blob of coefficients"
        );
        let domain = &self.domain;

        // Phase 1: for each offset u, the FFT of the circulant column of the u-th Toeplitz matrix.
        // The Toeplitz entries are c_t = f_{64 t + u}, laid out so the circulant product computes h_m:
        //
        //     e[0]         = c_63
        //     e[1..=65]    = 0
        //     e[128 - k]   = c_{63 - k}      for k = 1..62
        //
        // The 1 / 128 of the final inverse FFT is folded in here, on scalars instead of points.
        let size_inverse = Scalar::from_u64(CIRCULANT as u64)
            .invert()
            .unwrap_or(Scalar::ZERO);
        let mut transposed = vec![[Scalar::ZERO; FIELD_ELEMENTS_PER_CELL]; CIRCULANT];
        for u in 0..FIELD_ELEMENTS_PER_CELL {
            let block = |t: usize| coefficients[FIELD_ELEMENTS_PER_CELL * t + u];
            let mut e = [Scalar::ZERO; CIRCULANT];
            e[0] = block(BLOCKS - 1);
            for k in 1..BLOCKS - 1 {
                e[CIRCULANT - k] = block(BLOCKS - 1 - k);
            }
            domain.fft(&mut e);
            for (row, value) in transposed.iter_mut().zip(e) {
                row[u] = value * size_inverse;
            }
        }

        // Phase 2: the circulant products, summed over u, pointwise in the FFT domain.
        // Entry j is one MSM of 64 points: sum_u FFT(e_u)[j] * FFT(x_u)[j].
        let row_indices: Vec<usize> = (0..CIRCULANT).collect();
        let mut h: Vec<G1Projective> = Threads::available().map(&row_indices, |&j| {
            G1Projective::multi_exp(&self.rows[j], &transposed[j])
        });

        // Phase 3: back to the coefficient side, where the first 63 entries are h_0..h_62.
        // The rest are the circulant wraparound, not part of the Toeplitz product.
        domain.ifft_unscaled_parallel(&mut h);
        h[BLOCKS - 1..].fill(G1Projective::IDENTITY);

        // Phase 4: evaluate H at every root of unity of order 128.
        // The proof for cell k sits at a_k = w^{64 rev_7(k)}, so a bit reversal puts cells in order.
        let mut proofs = h;
        domain.fft_parallel(&mut proofs);
        domain.bit_reversal().permute(&mut proofs);
        debug_assert_eq!(proofs.len(), CELLS_PER_EXT_BLOB);
        proofs
    }
}

#[cfg(test)]
mod tests {
    use proptest::{collection::vec, prelude::*};

    use super::*;
    use crate::{Kzg, bit_reversal::BitReversal, fft::tests::arb_scalar};

    /// The FK20 tables of the shared mainnet context, built once for every test.
    fn tables() -> &'static Fk20 {
        Kzg::mainnet().cell_prover.fk20()
    }

    /// The spec's naive proof for one cell: divide by X^64 - h^64, then commit in the monomial basis.
    ///
    /// See compute_kzg_proof_multi_impl in the Fulu polynomial commitments sampling spec.
    fn naive_cell_proof(coefficients: &[Scalar], cell: usize) -> G1Projective {
        // The coset of cell k is h_k G_64 with h_k = w^{rev_7(k)}, w of order 8192.
        // Its vanishing polynomial is X^64 - h_k^64.
        let w = Scalar::root_of_unity(13).unwrap();
        let h = w.pow_vartime(&[BitReversal::new(7).index(cell) as u64]);
        let a = h.pow_vartime(&[FIELD_ELEMENTS_PER_CELL as u64]);

        // Synthetic division by X^64 - a, from the top coefficient down.
        //
        //     X^i = X^{i - 64} (X^64 - a) + a X^{i - 64}
        let mut remainder = coefficients.to_vec();
        let mut quotient = vec![Scalar::ZERO; coefficients.len() - FIELD_ELEMENTS_PER_CELL];
        for i in (FIELD_ELEMENTS_PER_CELL..coefficients.len()).rev() {
            quotient[i - FIELD_ELEMENTS_PER_CELL] = remainder[i];
            let carry = remainder[i] * a;
            remainder[i - FIELD_ELEMENTS_PER_CELL] += carry;
        }

        // Commit to the quotient of degree below 4032 with the first 4032 powers of s.
        Kzg::mainnet().cell_prover.monomial.commit(&quotient)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4))]

        #[test]
        fn fk20_matches_naive_proofs(
            sparse in vec((0..FIELD_ELEMENTS_PER_BLOB, arb_scalar()), 1..32),
            cells in vec(0..CELLS_PER_EXT_BLOB, 3),
        ) {
            // Fixture state: up to 31 random coefficients at random degrees, the rest zero.
            // Sparse inputs land in random blocks and offsets of the Toeplitz layout.
            let mut coefficients = vec![Scalar::ZERO; FIELD_ELEMENTS_PER_BLOB];
            for (degree, value) in sparse {
                coefficients[degree] = value;
            }

            // Three random cells per case pin FK20 against the spec's quadratic method.
            let proofs = tables().cell_proofs(&coefficients);
            for cell in cells {
                prop_assert_eq!(proofs[cell], naive_cell_proof(&coefficients, cell));
            }
        }
    }

    #[test]
    fn dense_polynomial_matches_naive_proofs() {
        // Fixture state: every coefficient is nonzero, f_i = i + 1.
        let coefficients: Vec<Scalar> = (1..=FIELD_ELEMENTS_PER_BLOB as u64)
            .map(Scalar::from_u64)
            .collect();
        let proofs = tables().cell_proofs(&coefficients);

        // The first and last cell of each half: original data, then extension.
        for cell in [0, 63, 64, 127] {
            assert_eq!(proofs[cell], naive_cell_proof(&coefficients, cell));
        }
    }
}
