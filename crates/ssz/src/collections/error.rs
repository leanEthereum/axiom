//! Errors building a collection from a value of the wrong length.

use std::{error::Error, fmt};

/// A collection built from too many elements, or from the wrong number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityError {
    /// A list received more elements than its limit.
    ExceedsLimit {
        /// The list's limit.
        limit: usize,
        /// Number of elements offered.
        length: usize,
    },
    /// A vector received a number of elements other than its length.
    WrongLength {
        /// The vector's length.
        expected: usize,
        /// Number of elements offered.
        length: usize,
    },
}

impl fmt::Display for CapacityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceedsLimit { limit, length } => {
                write!(f, "{length} elements exceed the limit of {limit}")
            }
            Self::WrongLength { expected, length } => {
                write!(f, "expected exactly {expected} elements, got {length}")
            }
        }
    }
}

impl Error for CapacityError {}
