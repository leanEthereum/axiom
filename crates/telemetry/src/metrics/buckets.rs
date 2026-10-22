//! Upper bounds of histogram buckets.

use std::sync::Arc;

use crate::metrics::BucketsError;

/// Bounds of the Prometheus client default buckets, in seconds.
///
/// They span a 5 ms RPC to a 10 s stall, which suits most request latencies.
/// Source: the default buckets of the official Go and Python clients.
const DEFAULT_BOUNDS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Finite, strictly increasing upper bounds of histogram buckets.
///
/// The infinite bucket is implicit and always last.
/// Clones share one list.
#[derive(Clone, Debug, PartialEq)]
pub struct Buckets {
    /// The finite bounds, strictly increasing.
    bounds: Arc<[f64]>,
}

impl Buckets {
    /// Checks bounds that must be finite and strictly increasing.
    ///
    /// An empty list is valid and leaves only the infinite bucket.
    pub fn new(bounds: &[f64]) -> Result<Self, BucketsError> {
        for (index, &bound) in bounds.iter().enumerate() {
            // Infinity and NaN cannot bound a finite bucket.
            if !bound.is_finite() {
                return Err(BucketsError::NotFinite { index, bound });
            }
            // Each bound must exceed its predecessor, or a bucket would be empty by construction.
            if index > 0 && bounds[index - 1] >= bound {
                return Err(BucketsError::NotIncreasing {
                    index,
                    bound,
                    previous: bounds[index - 1],
                });
            }
        }
        Ok(Self {
            bounds: Arc::from(bounds),
        })
    }

    /// A geometric series of bounds.
    ///
    /// ```text
    ///     start = 0.005, factor = 2, count = 4  ->  0.005, 0.01, 0.02, 0.04
    /// ```
    pub fn exponential(start: f64, factor: f64, count: usize) -> Result<Self, BucketsError> {
        // A series below or at zero, or one that does not grow, has no increasing bounds.
        let valid = start.is_finite() && start > 0.0 && factor.is_finite() && factor > 1.0;
        if !valid || count == 0 {
            return Err(BucketsError::InvalidSeries {
                start,
                factor,
                count,
            });
        }
        // Each bound is the previous one times the factor.
        let bounds: Vec<f64> = (0..count)
            .scan(start, |bound, _| {
                let current = *bound;
                *bound *= factor;
                Some(current)
            })
            .collect();
        // A long series may overflow to infinity, which the general check reports.
        Self::new(&bounds)
    }

    /// The finite bounds, in increasing order.
    #[must_use]
    pub fn bounds(&self) -> &[f64] {
        &self.bounds
    }
}

impl Default for Buckets {
    fn default() -> Self {
        // Invariant: the default bounds are finite and strictly increasing, so no check is needed.
        Self {
            bounds: Arc::from(DEFAULT_BOUNDS.as_slice()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        // Bound 1 is NaN, which equals nothing, so the log line is compared instead.
        let error = Buckets::new(&[1.0, f64::NAN]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "bucket bound NaN at index 1 is not finite"
        );

        // Bound 0 is the implicit last bucket written out.
        assert_eq!(
            Buckets::new(&[f64::INFINITY]),
            Err(BucketsError::NotFinite {
                index: 0,
                bound: f64::INFINITY
            })
        );

        // Bound 2 repeats bound 1.
        assert_eq!(
            Buckets::new(&[1.0, 2.0, 2.0]),
            Err(BucketsError::NotIncreasing {
                index: 2,
                bound: 2.0,
                previous: 2.0
            })
        );

        // Bound 1 falls below bound 0.
        assert_eq!(
            Buckets::new(&[0.5, 0.25]).unwrap_err().to_string(),
            "bucket bound 0.25 at index 1 does not exceed the previous bound 0.5"
        );

        // No bounds at all leaves one infinite bucket.
        assert_eq!(Buckets::new(&[]).map(|b| b.bounds().len()), Ok(0));
    }

    #[test]
    fn exponential_series() {
        // Doubling is exact in binary, so the bounds print as written.
        let buckets = Buckets::exponential(0.005, 2.0, 4).expect("valid series");
        assert_eq!(buckets.bounds(), &[0.005, 0.01, 0.02, 0.04]);

        // A zero start, a flat factor, and no buckets are all refused.
        assert_eq!(
            Buckets::exponential(0.0, 2.0, 4),
            Err(BucketsError::InvalidSeries {
                start: 0.0,
                factor: 2.0,
                count: 4
            })
        );
        assert_eq!(
            Buckets::exponential(1.0, 1.0, 4),
            Err(BucketsError::InvalidSeries {
                start: 1.0,
                factor: 1.0,
                count: 4
            })
        );
        assert_eq!(
            Buckets::exponential(1.0, 2.0, 0),
            Err(BucketsError::InvalidSeries {
                start: 1.0,
                factor: 2.0,
                count: 0
            })
        );

        // 1e300 times 10 overflows at bound 9.
        assert_eq!(
            Buckets::exponential(1e300, 10.0, 12),
            Err(BucketsError::NotFinite {
                index: 9,
                bound: f64::INFINITY
            })
        );
    }
}
