//! Square matrices over KoalaBear: a fast multiply for the rounds, and the algebra that derives them.

use crate::field::KoalaBear;

/// A dense WIDTH x WIDTH matrix that multiplies a state.
///
/// # Overview
///
/// The multiply accumulates integer products of canonical entries and Montgomery forms.
/// The form is linear: a sum of c_j * (x_j * 2^32) is the form of sum c_j * x_j.
/// So each output needs one reduction, and every product and sum stays in 64-bit lanes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DenseMatrix<const WIDTH: usize> {
    /// Canonical entries, row by row.
    rows: [[u64; WIDTH]; WIDTH],
    /// Whether a row's products sum below 2^63 without splitting, as with small entries.
    narrow: bool,
}

impl<const WIDTH: usize> DenseMatrix<WIDTH> {
    /// The matrix of canonical entries.
    pub(super) const fn new(rows: [[u64; WIDTH]; WIDTH]) -> Self {
        let mut largest = 0;
        let mut i = 0;
        while i < WIDTH {
            let mut j = 0;
            while j < WIDTH {
                if rows[i][j] > largest {
                    largest = rows[i][j];
                }
                j += 1;
            }
            i += 1;
        }
        // A row sums WIDTH products of an entry and a form below 2^31.
        let narrow = (largest as u128) * (WIDTH as u128) * (1 << 31) < (1 << 63);
        Self { rows, narrow }
    }

    /// The circulant matrix with this first row: entry (i, j) is row_((j - i) mod WIDTH).
    pub(super) const fn circulant(row: [u32; WIDTH]) -> Self {
        let mut rows = [[0; WIDTH]; WIDTH];
        let mut i = 0;
        while i < WIDTH {
            let mut j = 0;
            while j < WIDTH {
                rows[i][j] = row[(j + WIDTH - i) % WIDTH] as u64;
                j += 1;
            }
            i += 1;
        }
        Self::new(rows)
    }

    /// The matrix of field elements.
    pub(super) fn from_elements(elements: &FieldMatrix) -> Self {
        Self::new(std::array::from_fn(|i| {
            std::array::from_fn(|j| u64::from(elements.at(i, j).to_canonical()))
        }))
    }

    /// The entries as field elements.
    pub(super) fn elements(&self) -> FieldMatrix {
        FieldMatrix::new(
            self.rows
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|&entry| KoalaBear::new(entry as u32))
                        .collect()
                })
                .collect(),
        )
    }

    /// Multiplies a state in place.
    ///
    /// # Performance
    ///
    /// - Narrow: 16 products below 2^7 * 2^31 sum below 2^42.
    /// - Wide: each form splits into 16-bit halves, whose row sums stay below 2^52.
    ///
    /// ```text
    /// sum_j m_j * x_j = sum_j m_j * lo_j + 2^16 * sum_j m_j * hi_j
    /// ```
    pub(super) fn apply(&self, state: &mut [KoalaBear; WIDTH]) {
        let input = state.map(|word| u64::from(word.montgomery()));
        if self.narrow {
            for (out, row) in state.iter_mut().zip(&self.rows) {
                let sum: u64 = row.iter().zip(&input).map(|(&m, &x)| m * x).sum();
                *out = KoalaBear::from_montgomery_sum(sum);
            }
        } else {
            let low = input.map(|x| x & 0xffff);
            let high = input.map(|x| x >> 16);
            for (out, row) in state.iter_mut().zip(&self.rows) {
                let sum_low: u64 = row.iter().zip(&low).map(|(&m, &x)| m * x).sum();
                let sum_high: u64 = row.iter().zip(&high).map(|(&m, &x)| m * x).sum();
                *out = fold(u128::from(sum_low) + (u128::from(sum_high) << 16));
            }
        }
    }

    /// The textbook multiply, one 128-bit sum per output: the oracle of the fast one.
    #[cfg(test)]
    pub(super) fn apply_reference(&self, state: &mut [KoalaBear; WIDTH]) {
        let input = state.map(|word| u128::from(word.montgomery()));
        for (out, row) in state.iter_mut().zip(&self.rows) {
            // Bound: 24 products below 2^31 * 2^31 sum below 2^67, so 128 bits hold them.
            let sum = row
                .iter()
                .zip(&input)
                .map(|(&m, &x)| u128::from(m) * x)
                .sum();
            *out = fold(sum);
        }
    }
}

/// The element whose Montgomery form is congruent to a sum below 2^67.
///
/// # Algorithm
///
/// The prime's shape gives a cheap first fold, since 2^31 = 2^24 - 1 mod p.
///
/// ```text
/// sum = high * 2^31 + low
///     = high * (2^24 - 1) + low   mod p
/// ```
///
/// High is below 2^36, so the folded sum is below 2^61, inside the Montgomery reduction's range.
const fn fold(sum: u128) -> KoalaBear {
    let high = (sum >> 31) as u64;
    let low = (sum as u64) & ((1 << 31) - 1);
    KoalaBear::from_montgomery_sum(high * ((1 << 24) - 1) + low)
}

/// A square matrix of field elements, for deriving round matrices once at start-up.
///
/// Every entry is a public constant, so its algebra may branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FieldMatrix {
    /// Entries, row by row.
    rows: Vec<Vec<KoalaBear>>,
}

impl FieldMatrix {
    /// The matrix of these rows.
    pub(super) const fn new(rows: Vec<Vec<KoalaBear>>) -> Self {
        Self { rows }
    }

    /// The n x n identity.
    pub(super) fn identity(n: usize) -> Self {
        Self::new(
            (0..n)
                .map(|i| (0..n).map(|j| KoalaBear::new(u32::from(i == j))).collect())
                .collect(),
        )
    }

    /// Rows and columns.
    pub(super) const fn len(&self) -> usize {
        self.rows.len()
    }

    /// The entry at row i, column j.
    pub(super) fn at(&self, i: usize, j: usize) -> KoalaBear {
        self.rows[i][j]
    }

    /// The rows.
    pub(super) fn rows(&self) -> &[Vec<KoalaBear>] {
        &self.rows
    }

    /// The product self * other.
    pub(super) fn product(&self, other: &Self) -> Self {
        let n = self.len();
        Self::new(
            (0..n)
                .map(|i| {
                    (0..n)
                        .map(|j| {
                            (0..n).fold(KoalaBear::ZERO, |acc, k| {
                                acc + self.at(i, k) * other.at(k, j)
                            })
                        })
                        .collect()
                })
                .collect(),
        )
    }

    /// The product with a vector, self * v.
    pub(super) fn apply(&self, vector: &[KoalaBear]) -> Vec<KoalaBear> {
        self.rows
            .iter()
            .map(|row| {
                row.iter()
                    .zip(vector)
                    .fold(KoalaBear::ZERO, |acc, (&m, &x)| acc + m * x)
            })
            .collect()
    }

    /// The inverse by Gauss-Jordan elimination, none when singular.
    pub(super) fn inverse(&self) -> Option<Self> {
        let n = self.len();
        // Augment with the identity: [A | I] reduces to [I | A^-1].
        let identity = Self::identity(n);
        let mut rows: Vec<Vec<KoalaBear>> = self
            .rows
            .iter()
            .zip(&identity.rows)
            .map(|(row, unit)| [row.as_slice(), unit.as_slice()].concat())
            .collect();
        for column in 0..n {
            let pivot = (column..n).find(|&row| rows[row][column] != KoalaBear::ZERO)?;
            rows.swap(column, pivot);
            let scale = rows[column][column].inverse()?;
            for entry in &mut rows[column] {
                *entry *= scale;
            }
            let pivot_row = rows[column].clone();
            for (index, row) in rows.iter_mut().enumerate() {
                let factor = row[column];
                if index != column && factor != KoalaBear::ZERO {
                    for (entry, &pivot_entry) in row.iter_mut().zip(&pivot_row) {
                        *entry = *entry - factor * pivot_entry;
                    }
                }
            }
        }
        Some(Self::new(
            rows.into_iter().map(|row| row[n..].to_vec()).collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn wide_and_narrow_multiplies_match_the_textbook_sum(
            small in prop::collection::vec(0_u64..128, 256),
            large in prop::collection::vec(0..KoalaBear::ORDER, 576),
            state16 in prop::array::uniform16(0..KoalaBear::ORDER),
            state24 in prop::collection::vec(0..KoalaBear::ORDER, 24),
        ) {
            // A narrow 16 x 16 matrix and a wide 24 x 24 one, on random states and on all p - 1.
            let narrow = DenseMatrix::<16>::new(std::array::from_fn(|i| std::array::from_fn(|j| small[16 * i + j])));
            let wide = DenseMatrix::<24>::new(std::array::from_fn(|i| std::array::from_fn(|j| u64::from(large[24 * i + j]))));
            prop_assert!(narrow.narrow && !wide.narrow);

            let largest = KoalaBear::new(KoalaBear::ORDER - 1);
            for state in [state16.map(KoalaBear::new), [largest; 16]] {
                let (mut fast, mut expected) = (state, state);
                narrow.apply(&mut fast);
                narrow.apply_reference(&mut expected);
                prop_assert_eq!(fast, expected);
            }
            let state24: [KoalaBear; 24] = std::array::from_fn(|i| KoalaBear::new(state24[i]));
            for state in [state24, [largest; 24]] {
                let (mut fast, mut expected) = (state, state);
                wide.apply(&mut fast);
                wide.apply_reference(&mut expected);
                prop_assert_eq!(fast, expected);
            }
        }
    }

    #[test]
    fn fold_reduces_the_largest_sum() {
        // The largest sum the width-24 matrix produces: 24 products of p - 1 by p - 1.
        let p = u128::from(KoalaBear::ORDER);
        let sum = 24 * (p - 1) * (p - 1);
        assert_eq!(fold(sum).montgomery(), (sum % p) as u32);
    }

    #[test]
    fn inverse_times_matrix_is_the_identity() {
        // Fixture state: the 4 x 4 circulant matrix with first row 1, 2, 3, 4, then a singular one.
        let matrix = DenseMatrix::<4>::circulant([1, 2, 3, 4]).elements();
        let inverse = matrix.inverse().unwrap();
        assert_eq!(matrix.product(&inverse), FieldMatrix::identity(4));
        assert_eq!(inverse.product(&matrix), FieldMatrix::identity(4));

        // Rows 1, 1 and 2, 2 are dependent.
        let singular = FieldMatrix::new(vec![vec![KoalaBear::ONE; 2], vec![KoalaBear::new(2); 2]]);
        assert_eq!(singular.inverse(), None);
    }
}
