//! Errors raised while declaring metrics.

use std::{error::Error, fmt};

/// A registration the registry refuses.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryError {
    /// The metric name breaks the Prometheus name grammar.
    InvalidMetricName(String),

    /// The label name breaks the grammar or is reserved.
    InvalidLabelName(String),

    /// One metric declares the same label twice.
    DuplicateLabelName(String),

    /// Another metric already holds this name.
    DuplicateMetric(String),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetricName(name) => write!(f, "invalid metric name {name:?}"),
            Self::InvalidLabelName(name) => write!(f, "invalid or reserved label name {name:?}"),
            Self::DuplicateLabelName(name) => write!(f, "label {name:?} declared twice"),
            Self::DuplicateMetric(name) => write!(f, "metric {name:?} already registered"),
        }
    }
}

impl Error for RegistryError {}

/// A list of histogram bucket bounds that cannot form a histogram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BucketsError {
    /// The bound at this index is infinite or not a number.
    ///
    /// The infinite bucket is implicit and always last.
    NotFinite(usize),

    /// The bound at this index does not exceed the one before it.
    NotIncreasing(usize),

    /// An exponential series needs a positive start, a factor above one, and one bucket.
    InvalidSeries,
}

impl fmt::Display for BucketsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFinite(index) => write!(f, "bucket bound {index} is not finite"),
            Self::NotIncreasing(index) => {
                write!(f, "bucket bound {index} does not exceed the previous bound")
            }
            Self::InvalidSeries => f.write_str(
                "exponential buckets need a positive start, a factor above one, and a count",
            ),
        }
    }
}

impl Error for BucketsError {}
