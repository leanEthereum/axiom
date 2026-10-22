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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BucketsError {
    /// The bound at this index is infinite or not a number.
    ///
    /// The infinite bucket is implicit and always last.
    #[error("bucket bound {0} is not finite")]
    NotFinite(usize),

    /// The bound at this index does not exceed the one before it.
    #[error("bucket bound {0} does not exceed the previous bound")]
    NotIncreasing(usize),

    /// An exponential series needs a positive start, a factor above one, and one bucket.
    #[error("exponential buckets need a positive start, a factor above one, and a count")]
    InvalidSeries,
}
