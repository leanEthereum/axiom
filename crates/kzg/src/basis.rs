//! A basis of G1 points from the trusted setup, which commits to a polynomial in one MSM.

use axiom_bls12_381::{G1Affine, G1Projective, Scalar};

use crate::parallel::Threads;

/// Below this many points per thread, a multi-scalar multiplication stays on one thread.
///
/// Spawning a thread costs tens of microseconds.
/// A 256-point MSM costs a few milliseconds, so smaller splits stop paying for themselves.
const MIN_POINTS_PER_THREAD: usize = 256;

/// The images [b_i(s)] of a polynomial basis b_i at the secret point s.
///
/// The monomial basis commits coefficients, the Lagrange basis commits evaluations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Basis(Vec<G1Affine>);

impl Basis {
    /// Wraps the decoded points, in basis order.
    pub(crate) const fn new(points: Vec<G1Affine>) -> Self {
        Self(points)
    }

    /// The points, in basis order.
    pub(crate) fn points(&self) -> &[G1Affine] {
        &self.0
    }

    /// The first points only, the basis of the polynomials of lower degree.
    pub(crate) fn prefix(&self, length: usize) -> Self {
        Self(self.0[..length].to_vec())
    }

    /// Commits to sum_i k_i b_i, splitting large inputs into one Pippenger MSM per core.
    ///
    /// The scalars meet the first points of the basis, so a shorter input commits a lower degree.
    /// They must be public, as for every multi-scalar multiplication of the curve crate.
    ///
    /// # Panics
    ///
    /// Panics when there are more scalars than points.
    pub(crate) fn commit(&self, scalars: &[Scalar]) -> G1Projective {
        let points = &self.0[..scalars.len()];

        // Threshold: each thread needs enough points to amortize its spawn.
        let threads = Threads::available();
        let count = threads.split(points.len() / MIN_POINTS_PER_THREAD);
        if count <= 1 {
            return G1Projective::multi_exp(points, scalars);
        }

        // Split both slices at the same boundaries, then add the partial sums.
        //
        //     sum_{i < n} k_i P_i = sum_t ( sum_{i in chunk t} k_i P_i )
        let chunk = points.len().div_ceil(count);
        let pairs: Vec<(&[G1Affine], &[Scalar])> =
            points.chunks(chunk).zip(scalars.chunks(chunk)).collect();
        let partial_sums: Vec<G1Projective> = threads.map(&pairs, |(points, scalars)| {
            G1Projective::multi_exp(points, scalars)
        });
        partial_sums.into_iter().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_msm_matches_single_msm() {
        // Fixture state: 2048 points, enough for up to 8 threads of 256 points.
        //
        //     P_i = (i + 1) G and k_i = i + 2, so the sum is sum_i (i + 1)(i + 2) G.
        let scalars: Vec<Scalar> = (0..2048).map(|i| Scalar::from_u64(i + 2)).collect();
        let points: Vec<G1Affine> = (0..2048)
            .map(|i| G1Affine::from(G1Projective::GENERATOR.mul_vartime(&Scalar::from_u64(i + 1))))
            .collect();
        let basis = Basis::new(points.clone());
        assert_eq!(
            basis.commit(&scalars),
            G1Projective::multi_exp(&points, &scalars)
        );

        // Two scalars meet the first two points only: 2 * 1 G + 3 * 2 G = 8 G.
        assert_eq!(
            basis.commit(&scalars[..2]),
            G1Projective::GENERATOR.mul_vartime(&Scalar::from_u64(8))
        );
    }
}
