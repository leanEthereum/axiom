//! The partial rounds rewritten with scalar constants and sparse matrices, computing the same permutation.
//!
//! # Overview
//!
//! A textbook partial round adds WIDTH constants, cubes word 0, and multiplies by the dense MDS matrix M.
//! Only word 0 is non-linear, which allows two exact rewrites, per the Poseidon paper, appendix B.
//!
//! Constants: words 1 and up pass the S-box unchanged, so their constants commute with it.
//! Each round keeps the constant of word 0 and pushes the rest through M into the next round.
//!
//! ```text
//! v_r     = c_r + carry_(r-1)
//! k_r     = v_r[0]
//! carry_r = M * (0, v_r[1..])
//! ```
//!
//! The last carry joins the constants of the first terminal full round.
//!
//! Matrices: any matrix X splits as X = S * D, with D = diag(1, X_hat) and S sparse.
//!
//! ```text
//! X = [ x_00   x_row^T ]    S = [ x_00   x_row^T * X_hat^-1 ]    D = [ 1   0     ]
//!     [ x_col  X_hat   ]        [ x_col  I                  ]        [ 0   X_hat ]
//! ```
//!
//! D leaves word 0 alone, so it commutes with the round's S-box and slides into the round before.
//! Splitting from the last round back, every partial round keeps a sparse S_r.
//! The final D_0 merges into the matrix of the last initial full round.
//!
//! A sparse round costs 2 * WIDTH products instead of WIDTH^2.

use crate::{
    field::KoalaBear,
    poseidon::matrix::{DenseMatrix, FieldMatrix},
};

/// One partial round in sparse form: a scalar constant, the cube of word 0, then S_r.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SparseRound<const WIDTH: usize> {
    /// The constant added to word 0 before the S-box.
    constant: KoalaBear,
    /// The first row of S_r; entry 0 is its corner.
    row: [KoalaBear; WIDTH],
    /// The first column of S_r below the corner; entry 0 is unused.
    column: [KoalaBear; WIDTH],
}

impl<const WIDTH: usize> SparseRound<WIDTH> {
    /// Applies the round in place.
    fn apply(&self, state: &mut [KoalaBear; WIDTH]) {
        let first = (state[0] + self.constant).cube();
        // Row 0 reads the old words; rows 1 and up add a multiple of word 0 to themselves.
        let mut out = self.row[0] * first;
        for ((word, &row), &column) in state.iter_mut().zip(&self.row).zip(&self.column).skip(1) {
            out += row * *word;
            *word += column * first;
        }
        state[0] = out;
    }
}

/// The partial rounds of one instance in their fast form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PartialRounds<const WIDTH: usize> {
    /// D_0 * M, which replaces M in the last initial full round.
    pub(super) entry_matrix: DenseMatrix<WIDTH>,
    /// The rounds, in order.
    rounds: Vec<SparseRound<WIDTH>>,
    /// The constants left after the last round, added to the first terminal round's.
    pub(super) residual: [KoalaBear; WIDTH],
}

impl<const WIDTH: usize> PartialRounds<WIDTH> {
    /// The fast form of textbook partial rounds with these constants and MDS matrix.
    ///
    /// # Panics
    ///
    /// Panics when a lower-right block is singular, which an MDS matrix rules out.
    pub(super) fn new(mds: &FieldMatrix, constants: &[[KoalaBear; WIDTH]]) -> Self {
        // Phase 1: constants. Each round keeps word 0's and carries the rest forward.
        let mut carry = [KoalaBear::ZERO; WIDTH];
        let mut scalars = Vec::with_capacity(constants.len());
        for round in constants {
            let mut pushed: [KoalaBear; WIDTH] = std::array::from_fn(|i| round[i] + carry[i]);
            scalars.push(pushed[0]);
            pushed[0] = KoalaBear::ZERO;
            carry = mds
                .apply(&pushed)
                .try_into()
                .expect("a square matrix keeps the width");
        }

        // Phase 2: matrices, from the last round back.
        let mut sparse = Vec::with_capacity(constants.len());
        let mut current = mds.clone();
        for _ in constants {
            let (round_matrix, lower) = Self::split(&current);
            sparse.push(round_matrix);
            // D = diag(1, X_hat) slides into the round before, onto its M.
            current = Self::block(&lower).product(mds);
        }
        sparse.reverse();

        let rounds = sparse
            .into_iter()
            .zip(scalars)
            .map(|((row, column), constant)| SparseRound {
                constant,
                row,
                column,
            })
            .collect();
        Self {
            entry_matrix: DenseMatrix::from_elements(&current),
            rounds,
            residual: carry,
        }
    }

    /// Splits X = S * diag(1, X_hat): returns S's first row and column, and X_hat.
    fn split(x: &FieldMatrix) -> (([KoalaBear; WIDTH], [KoalaBear; WIDTH]), FieldMatrix) {
        let lower = FieldMatrix::new(x.rows()[1..].iter().map(|row| row[1..].to_vec()).collect());
        // Invariant: every square submatrix of an MDS matrix is invertible.
        let inverse = lower
            .inverse()
            .expect("an MDS matrix has invertible blocks");

        // The row: x_row^T * X_hat^-1, with the corner x_00 first.
        let mut row = [KoalaBear::ZERO; WIDTH];
        row[0] = x.at(0, 0);
        for (j, slot) in row.iter_mut().enumerate().skip(1) {
            *slot = (1..WIDTH).fold(KoalaBear::ZERO, |acc, k| {
                acc + x.at(0, k) * inverse.at(k - 1, j - 1)
            });
        }
        let column = std::array::from_fn(|i| if i == 0 { KoalaBear::ZERO } else { x.at(i, 0) });
        ((row, column), lower)
    }

    /// The block-diagonal matrix diag(1, block).
    fn block(lower: &FieldMatrix) -> FieldMatrix {
        FieldMatrix::new(
            (0..WIDTH)
                .map(|i| {
                    (0..WIDTH)
                        .map(|j| match (i, j) {
                            (0, 0) => KoalaBear::ONE,
                            (0, _) | (_, 0) => KoalaBear::ZERO,
                            _ => lower.at(i - 1, j - 1),
                        })
                        .collect()
                })
                .collect(),
        )
    }

    /// Applies every partial round in place.
    pub(super) fn apply(&self, state: &mut [KoalaBear; WIDTH]) {
        for round in &self.rounds {
            round.apply(state);
        }
    }
}
