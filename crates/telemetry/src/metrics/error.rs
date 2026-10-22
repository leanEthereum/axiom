//! Errors raised while declaring metrics.

use thiserror::Error;

/// A registration the registry refuses.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// The metric name breaks the Prometheus name grammar.
    #[error("invalid metric name {0:?}")]
    InvalidMetricName(String),

    /// The label name breaks the grammar or is reserved.
    #[error("invalid or reserved label name {0:?}")]
    InvalidLabelName(String),

    /// One metric declares the same label twice.
    #[error("label {0:?} declared twice")]
    DuplicateLabelName(String),

    /// Another metric already holds this name.
    #[error("metric {0:?} already registered")]
    DuplicateMetric(String),
}

/// A list of histogram bucket bounds that cannot form a histogram.
///
/// The bounds are floats, so the error compares partially, never totally.
#[derive(Clone, Copy, Debug, PartialEq, Error)]
#[non_exhaustive]
pub enum BucketsError {
    /// A bound is infinite or not a number.
    ///
    /// The infinite bucket is implicit and always last.
    #[error("bucket bound {bound} at index {index} is not finite")]
    NotFinite {
        /// The bound's position in the list.
        index: usize,
        /// The offending bound.
        bound: f64,
    },

    /// A bound does not exceed the one before it.
    #[error("bucket bound {bound} at index {index} does not exceed the previous bound {previous}")]
    NotIncreasing {
        /// The bound's position in the list.
        index: usize,
        /// The offending bound.
        bound: f64,
        /// The bound right before it.
        previous: f64,
    },

    /// An exponential series needs a positive start, a factor above one, and one bucket.
    #[error(
        "exponential buckets need a positive start, a factor above one, and a count, \
         got start {start}, factor {factor}, count {count}"
    )]
    InvalidSeries {
        /// The first bound requested.
        start: f64,
        /// The ratio between consecutive bounds.
        factor: f64,
        /// The number of bounds requested.
        count: usize,
    },
}
