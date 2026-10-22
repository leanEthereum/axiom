//! Radix-2 fast Fourier transforms over the scalar field, and over G1 for FK20.
//!
//! # Overview
//!
//! A domain of size n = 2^k is the group of n-th roots of unity, powers of a primitive root omega.
//! The forward transform maps coefficients to evaluations, both in natural order:
//!
//! ```text
//!     out_j = sum_i a_i omega^{i j}        evaluations of sum_i a_i X^i at omega^j
//! ```
//!
//! The inverse transform runs the same network with omega^{-1}, then divides by n.
//! A coset transform evaluates at shift * omega^j instead, by first scaling a_i by shift^i.
//!
//! The specs store evaluations in bit-reversal order, so the transforms pair with a permutation.

use std::ops::{Add, Sub};

use axiom_bls12_381::{G1Projective, Scalar};

use crate::{bit_reversal::BitReversal, parallel::Threads, powers::Powers};

/// A value the transforms can process: an element of a module over the scalar field.
///
/// Scalars transform polynomials.
/// G1 points transform the commitment vectors of FK20, with the same butterflies.
pub(crate) trait FftElement: Copy + Send + Add<Output = Self> + Sub<Output = Self> {
    /// Multiplies by a public scalar.
    fn scale(&self, factor: &Scalar) -> Self;
}

impl FftElement for Scalar {
    #[inline]
    fn scale(&self, factor: &Scalar) -> Self {
        self * factor
    }
}

impl FftElement for G1Projective {
    #[inline]
    fn scale(&self, factor: &Scalar) -> Self {
        // Twiddle factors are public roots of unity, so the variable-time ladder is safe.
        self.mul_vartime(factor)
    }
}

/// The multiplicative subgroup of order 2^k of the scalar field, with its precomputed roots.
#[derive(Clone, Debug)]
pub(crate) struct Domain {
    /// Base-two logarithm of the size.
    log_size: u32,
    /// The powers omega^0, ..., omega^{n-1} of the primitive root, in natural order.
    roots: Vec<Scalar>,
    /// The powers omega^0, omega^{-1}, ..., omega^{-(n-1)}.
    inverse_roots: Vec<Scalar>,
    /// The inverse of the size, which completes the inverse transform.
    size_inverse: Scalar,
}

impl Domain {
    /// Builds the domain of size 2^k from the specs' primitive root.
    ///
    /// The root is 7^((r - 1) / 2^k), as compute_roots_of_unity derives it in the Deneb spec.
    ///
    /// # Panics
    ///
    /// Panics when k exceeds the 2-adicity 32 of the field.
    pub(crate) fn new(log_size: u32) -> Self {
        // The field's root of order 2^32 is 7^t for the odd part t of r - 1.
        // Squaring it 32 - k times gives 7^((r - 1) / 2^k), the spec's root.
        let Some(root) = Scalar::root_of_unity(log_size) else {
            panic!("the scalar field has no root of unity of order 2^{log_size}");
        };
        let size = 1_usize << log_size;

        // Successive powers of the root, and of its inverse.
        //
        //     omega^{-i} = omega^{n - i}, so the inverse table reads the forward one backwards.
        let roots: Vec<Scalar> = Powers::new(root).take(size).collect();
        let inverse_roots = (0..size).map(|i| roots[(size - i) % size]).collect();

        // n < r, so n is a nonzero field element with an inverse.
        let size_inverse = Scalar::from_u64(size as u64)
            .invert()
            .unwrap_or(Scalar::ZERO);
        Self {
            log_size,
            roots,
            inverse_roots,
            size_inverse,
        }
    }

    /// Number of points in the domain.
    pub(crate) const fn size(&self) -> usize {
        1 << self.log_size
    }

    /// The bit-reversal permutation of the domain's size, the order the specs store evaluations in.
    pub(crate) const fn bit_reversal(&self) -> BitReversal {
        BitReversal::new(self.log_size)
    }

    /// The inverse of the size, 1 / n.
    pub(crate) const fn size_inverse(&self) -> Scalar {
        self.size_inverse
    }

    /// The domain points omega^i, in natural order.
    pub(crate) fn roots(&self) -> &[Scalar] {
        &self.roots
    }

    /// The inverses omega^{-i} of the domain points, in natural order.
    pub(crate) fn inverse_roots(&self) -> &[Scalar] {
        &self.inverse_roots
    }

    /// Replaces coefficients by evaluations over the domain, both in natural order.
    ///
    /// # Panics
    ///
    /// Panics when the input length differs from the domain size.
    pub(crate) fn fft<T: FftElement>(&self, values: &mut [T]) {
        self.butterflies(values, &self.roots, false);
    }

    /// Replaces evaluations over the domain by coefficients, both in natural order.
    ///
    /// # Panics
    ///
    /// Panics when the input length differs from the domain size.
    pub(crate) fn ifft<T: FftElement>(&self, values: &mut [T]) {
        // The network with inverse roots computes n times the coefficients.
        self.butterflies(values, &self.inverse_roots, false);
        for value in values.iter_mut() {
            *value = value.scale(&self.size_inverse);
        }
    }

    /// The forward transform with each layer's butterflies spread over all cores.
    ///
    /// It pays off for G1 points only, where one butterfly costs a scalar multiplication.
    pub(crate) fn fft_parallel<T: FftElement>(&self, values: &mut [T]) {
        self.butterflies(values, &self.roots, true);
    }

    /// The inverse transform on all cores, without the final division by the size.
    ///
    /// FK20 folds that division into its scalars, so no G1 point is ever scaled by 1 / n.
    pub(crate) fn ifft_unscaled_parallel<T: FftElement>(&self, values: &mut [T]) {
        self.butterflies(values, &self.inverse_roots, true);
    }

    /// Replaces coefficients by evaluations over the coset shift * omega^i.
    ///
    /// ```text
    ///     f(shift * omega^j) = sum_i (a_i shift^i) omega^{i j}
    /// ```
    pub(crate) fn coset_fft(&self, values: &mut [Scalar], shift: &Scalar) {
        // Scale a_i by shift^i, then evaluate over the plain domain.
        for (value, power) in values.iter_mut().zip(Powers::new(*shift)) {
            *value *= power;
        }
        self.fft(values);
    }

    /// Replaces evaluations over the coset shift * omega^i by coefficients.
    pub(crate) fn coset_ifft(&self, values: &mut [Scalar], shift: &Scalar) {
        // Interpolate the shifted polynomial f(shift X), then undo the shift on each coefficient.
        self.ifft(values);
        let shift_inverse = shift.invert().unwrap_or(Scalar::ZERO);
        for (value, power) in values.iter_mut().zip(Powers::new(shift_inverse)) {
            *value *= power;
        }
    }

    /// The iterative Cooley-Tukey network: a bit-reversal permutation, then log_2(n) layers.
    ///
    /// # Algorithm
    ///
    /// Layer s merges pairs of transforms of size m / 2 into transforms of size m = 2^s.
    ///
    /// ```text
    ///     u = x[j]            v = x[j + m/2] * w^{j n / m}
    ///     x[j] = u + v        x[j + m/2] = u - v
    /// ```
    ///
    /// The first twiddle of each block is one, so the scaling is skipped there.
    /// That saves a full scalar multiplication per block when the elements are G1 points.
    ///
    /// # Performance
    ///
    /// In parallel mode, the butterflies of each layer split over all cores.
    fn butterflies<T: FftElement>(&self, values: &mut [T], roots: &[Scalar], parallel: bool) {
        let size = self.size();
        assert_eq!(
            values.len(),
            size,
            "transform length must equal the domain size"
        );

        // Phase 1: put the inputs in bit-reversed order, so each layer works in place.
        self.bit_reversal().permute(values);

        // Phase 2: merge transforms of doubling size.
        let mut half = 1;
        while half < size {
            // The twiddle step: block size 2 * half uses every (n / (2 * half))-th root.
            let stride = size / (2 * half);
            let pairs = values.chunks_exact_mut(2 * half).flat_map(|block| {
                let (low, high) = block.split_at_mut(half);
                low.iter_mut().zip(high).enumerate()
            });

            // The butterflies of one layer touch disjoint pairs, so they may run in any order.
            let butterfly = |(j, (u, v)): &mut (usize, (&mut T, &mut T))| {
                let t = if *j == 0 {
                    **v
                } else {
                    v.scale(&roots[*j * stride])
                };
                let sum = **u + t;
                **v = **u - t;
                **u = sum;
            };
            if parallel {
                let mut pairs: Vec<_> = pairs.collect();
                Threads::available().for_each_mut(&mut pairs, butterfly);
            } else {
                pairs.for_each(|mut pair| butterfly(&mut pair));
            }
            half *= 2;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::{collection::vec, prelude::*};

    use super::*;

    /// Scalars drawn by reducing 32 random bytes.
    pub(crate) fn arb_scalar() -> impl Strategy<Value = Scalar> {
        any::<[u8; 32]>().prop_map(|bytes| Scalar::from_bytes_be_reduced(&bytes))
    }

    /// Evaluates sum_i a_i x^i by Horner's rule, the reference for every transform.
    pub(crate) fn horner(coefficients: &[Scalar], x: &Scalar) -> Scalar {
        coefficients
            .iter()
            .rev()
            .fold(Scalar::ZERO, |acc, coefficient| acc * x + coefficient)
    }

    #[test]
    fn roots_match_the_spec_derivation() {
        // The spec derives omega_n = 7^((r - 1) / n).
        // For n = 4096, (r - 1) / 4096 = (r - 1) >> 12, written out as limbs.
        //
        //     r - 1 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
        let exponent = [
            0xbfef_ffff_fff0_0000,
            0x8055_3bda_402f_ffe5,
            0xd483_339d_8080_9a1d,
            0x0007_3eda_7532_99d7,
        ];
        let expected = Scalar::from_u64(7).pow_vartime(&exponent);
        let domain = Domain::new(12);
        assert_eq!(domain.roots()[1], expected);
        // Inverse roots undo the forward ones.
        assert_eq!(domain.roots()[5] * domain.inverse_roots()[5], Scalar::ONE);
    }

    #[test]
    fn transform_of_size_one_is_identity() {
        // The domain {1} evaluates a constant polynomial to itself.
        let domain = Domain::new(0);
        let mut values = [Scalar::from_u64(9)];
        domain.fft(&mut values);
        assert_eq!(values, [Scalar::from_u64(9)]);
    }

    proptest! {
        #[test]
        fn fft_matches_horner(coefficients in vec(arb_scalar(), 16)) {
            // Each output is the polynomial evaluated at omega^j.
            let domain = Domain::new(4);
            let mut values = coefficients.clone();
            domain.fft(&mut values);
            for (value, root) in values.iter().zip(domain.roots()) {
                prop_assert_eq!(*value, horner(&coefficients, root));
            }
        }

        #[test]
        fn ifft_inverts_fft(coefficients in vec(arb_scalar(), 256)) {
            // Coefficients -> evaluations -> coefficients is the identity.
            let domain = Domain::new(8);
            let mut values = coefficients.clone();
            domain.fft(&mut values);
            domain.ifft(&mut values);
            prop_assert_eq!(values, coefficients);
        }

        #[test]
        fn coset_ifft_inverts_coset_fft(coefficients in vec(arb_scalar(), 64), shift in arb_scalar()) {
            prop_assume!(!shift.is_zero());
            // Evaluations over shift * omega^j match Horner, and interpolation restores the input.
            let domain = Domain::new(6);
            let mut values = coefficients.clone();
            domain.coset_fft(&mut values, &shift);
            prop_assert_eq!(values[3], horner(&coefficients, &(shift * domain.roots()[3])));
            domain.coset_ifft(&mut values, &shift);
            prop_assert_eq!(values, coefficients);
        }

        #[test]
        fn g1_fft_commutes_with_commitment(coefficients in vec(arb_scalar(), 8)) {
            // FFT over [a_i] G equals [FFT(a)_j] G, so the G1 network is the scalar one in the exponent.
            // The parallel network must agree with the sequential reference.
            let domain = Domain::new(3);
            let mut points: Vec<G1Projective> = coefficients
                .iter()
                .map(|a| G1Projective::GENERATOR.mul_vartime(a))
                .collect();
            let coefficients_copy = coefficients.clone();
            let mut scalars = coefficients;
            let mut sequential = points.clone();
            domain.fft_parallel(&mut points);
            domain.fft(&mut sequential);
            domain.fft(&mut scalars);
            prop_assert_eq!(&points, &sequential);
            for (point, scalar) in points.iter().zip(&scalars) {
                prop_assert_eq!(*point, G1Projective::GENERATOR.mul_vartime(scalar));
            }

            // The parallel inverse network undoes the forward one, up to the factor n = 8.
            domain.ifft_unscaled_parallel(&mut points);
            let eight = Scalar::from_u64(8);
            for (point, coefficient) in points.iter().zip(&coefficients_copy) {
                prop_assert_eq!(*point, G1Projective::GENERATOR.mul_vartime(&(coefficient * &eight)));
            }
        }
    }
}
