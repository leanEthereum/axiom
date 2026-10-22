//! Multi-scalar multiplication by Pippenger's bucket method, shared by G1 and G2.
//!
//! # Overview
//!
//! The goal is sum_i k_i P_i for n points, far cheaper than n separate multiplications.
//! Each 255-bit scalar splits into windows of c bits.
//! Within one window, every point drops into the bucket named by its c-bit digit.
//!
//! ```text
//!     window sum = sum_{d=1}^{2^c - 1} d * bucket_d
//!                = bucket_{2^c-1}
//!                + (bucket_{2^c-1} + bucket_{2^c-2})
//!                + ...                                  (running sums, top bucket first)
//! ```
//!
//! The windows then combine by Horner's rule: shift by c doublings, add the next window.
//! Cost: about (b / c) * (n + 2^c) additions for b-bit scalars, minimized near c = log_2(n) - 2.

use std::ops::AddAssign;

use crate::Scalar;

/// The group operations the bucket method needs.
///
/// G1 and G2 both implement it with their projective point type.
pub(crate) trait PippengerGroup:
    Copy + for<'a> AddAssign<&'a Self> + for<'a> AddAssign<&'a Self::Affine>
{
    /// The affine form of the input points, added into buckets by mixed addition.
    type Affine;

    /// The group identity.
    const NEUTRAL: Self;

    /// Returns 2 * self.
    fn double_point(&self) -> Self;

    /// Computes sum_i k_i P_i over paired points and scalars.
    ///
    /// The running time depends on the scalars, so they must be public.
    ///
    /// # Panics
    ///
    /// Panics when the two slices differ in length.
    fn pippenger(points: &[Self::Affine], scalars: &[Scalar]) -> Self {
        assert_eq!(
            points.len(),
            scalars.len(),
            "multi-scalar multiplication needs one scalar per point"
        );
        if points.is_empty() {
            return Self::NEUTRAL;
        }

        // Phase 1: leave Montgomery form once, so digits can be read off the integer bits.
        let digits = Digits::new(scalars);

        // Phase 2: process windows from the most significant down, Horner style.
        let mut buckets = vec![Self::NEUTRAL; (1 << digits.width) - 1];
        let mut result = Self::NEUTRAL;
        for window in (0..digits.windows).rev() {
            // Shift the accumulated windows left by c bits.
            for _ in 0..digits.width {
                result = result.double_point();
            }

            // Drop each point into the bucket of its digit.
            // Digit 0 contributes nothing.
            buckets.fill(Self::NEUTRAL);
            for (index, point) in points.iter().enumerate() {
                let digit = digits.digit(index, window);
                if digit != 0 {
                    buckets[digit - 1] += point;
                }
            }

            // Weighted bucket sum through running sums, top bucket first.
            //
            //     running after bucket d = sum_{e >= d} bucket_e
            //     sum of all runnings    = sum_d d * bucket_d
            let mut running = Self::NEUTRAL;
            let mut window_sum = Self::NEUTRAL;
            for bucket in buckets.iter().rev() {
                running += bucket;
                window_sum += &running;
            }
            result += &window_sum;
        }
        result
    }
}

/// The scalars of one multiplication as canonical integers, read in windows of c-bit digits.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Digits {
    /// The canonical little-endian limbs of each scalar.
    scalars: Vec<[u64; 4]>,
    /// The window width c, in bits.
    width: usize,
    /// Windows below the longest scalar, the only ones that can hold a nonzero digit.
    windows: usize,
}

impl Digits {
    /// Reads the scalars, choosing the window width for their count.
    fn new(scalars: &[Scalar]) -> Self {
        let scalars: Vec<[u64; 4]> = scalars.iter().map(Scalar::to_canonical).collect();
        let width = Self::window_width(scalars.len());

        // Short scalars, such as 128-bit batch coefficients, skip the empty top windows.
        let bits = scalars.iter().map(Self::bit_length).max().unwrap_or(0);
        Self {
            windows: bits.div_ceil(width),
            scalars,
            width,
        }
    }

    /// Chooses the window width c for n points.
    ///
    /// The value approximates ln(n) + 2, which tracks the cost minimum of (255 / c)(n + 2^c).
    fn window_width(n: usize) -> usize {
        // ln(n) = log_2(n) * ln(2), with ln(2) approximated by 69 / 100.
        let log2 = usize::try_from(n.ilog2()).unwrap_or(0);
        (log2 * 69 / 100 + 2).clamp(2, 16)
    }

    /// Number of significant bits of a little-endian integer, zero for zero.
    fn bit_length(limbs: &[u64; 4]) -> usize {
        // The highest nonzero limb decides.
        // Each limb below it contributes 64 bits.
        limbs
            .iter()
            .rposition(|limb| *limb != 0)
            .map_or(0, |top| 64 * top + 64 - limbs[top].leading_zeros() as usize)
    }

    /// The digit of one scalar in one window.
    fn digit(&self, index: usize, window: usize) -> usize {
        Self::read(&self.scalars[index], window * self.width, self.width)
    }

    /// Reads the width-bit digit starting at bit offset start of a little-endian integer.
    fn read(limbs: &[u64; 4], start: usize, width: usize) -> usize {
        let limb = start / 64;
        let shift = start % 64;

        // Low part of the digit from the limb holding its first bit.
        let mut bits = limbs[limb] >> shift;

        // A digit straddling a limb boundary takes its high part from the next limb.
        //
        //     limb k+1 = [ ....hhhh ]
        //     limb k   = [ llll........ ]
        //
        // The digit starts at the first low bit l of limb k, and its high bits h sit in limb k+1.
        if shift + width > 64 && limb + 1 < limbs.len() {
            bits |= limbs[limb + 1] << (64 - shift);
        }
        usize::try_from(bits & ((1 << width) - 1)).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_straddle_limb_boundaries() {
        // Fixture state: bits 60..67 hold 0xab, split across limbs 0 and 1.
        //
        //     limb 0 bits 60..63 = 0xb, limb 1 bits 0..3 = 0xa
        let limbs = [0xb000_0000_0000_0000, 0x0000_0000_0000_000a, 0, 0];
        assert_eq!(Digits::read(&limbs, 60, 8), 0xab);
        // The top window reads past bit 255 only into implicit zeros.
        assert_eq!(Digits::read(&[0, 0, 0, 1 << 63], 252, 8), 0x8);
    }

    #[test]
    fn bit_length_counts_significant_bits() {
        // Zero has no bits, one has one, and 2^128 needs 129.
        assert_eq!(Digits::bit_length(&[0, 0, 0, 0]), 0);
        assert_eq!(Digits::bit_length(&[1, 0, 0, 0]), 1);
        assert_eq!(Digits::bit_length(&[0, 0, 1, 0]), 129);
    }

    #[test]
    fn window_width_grows_with_input_size() {
        // A blob-sized input of 4096 points uses 10-bit windows.
        assert_eq!(Digits::window_width(4096), 10);
        // Tiny inputs keep the minimum width.
        assert_eq!(Digits::window_width(1), 2);
    }

    #[test]
    fn short_scalars_skip_empty_top_windows() {
        // Two scalars of at most 9 bits, 7 and 300, need 2-bit windows and five of them.
        let digits = Digits::new(&[Scalar::from_u64(7), Scalar::from_u64(300)]);
        assert_eq!(digits.width, 2);
        assert_eq!(digits.windows, 5);
        // 300 = 0b1_0010_1100: window 2 holds bits 4..5, which are 0b10.
        assert_eq!(digits.digit(1, 2), 0b10);
    }
}
