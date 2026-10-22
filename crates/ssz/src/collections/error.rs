//! Errors building a collection from a value of the wrong length.

use thiserror::Error;

/// A collection built from too many elements, or from the wrong number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CapacityError {
    /// A list received more elements than its limit.
    #[error("{length} elements exceed the limit of {limit}")]
    ExceedsLimit {
        /// The list's limit.
        limit: usize,
        /// Number of elements offered.
        length: usize,
    },
    /// A vector received a number of elements other than its length.
    #[error("expected exactly {expected} elements, got {length}")]
    WrongLength {
        /// The vector's length.
        expected: usize,
        /// Number of elements offered.
        length: usize,
    },
}
