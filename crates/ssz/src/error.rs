//! Reasons a byte string fails to decode.

use thiserror::Error;

/// A byte string that is not the encoding of any value of the expected type.
///
/// Every variant names the rule the input broke.
/// Decoders reject at the first broken rule, so one input yields one error.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// A fixed-size value received the wrong number of bytes.
    #[error("expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Length the type requires.
        expected: usize,
        /// Length the input had.
        actual: usize,
    },

    /// The input ended before a fixed-size part or an offset was complete.
    #[error("expected at least {minimum} bytes, got {actual}")]
    TooShort {
        /// Minimum length the type requires.
        minimum: usize,
        /// Length the input had.
        actual: usize,
    },

    /// The first offset does not point right past the fixed-size part.
    ///
    /// Any other value would leave unread bytes or overlap the fixed part.
    #[error("first offset is {actual}, fixed part ends at {expected}")]
    FirstOffsetMismatch {
        /// Length of the fixed-size part.
        expected: usize,
        /// Offset found in the input.
        actual: usize,
    },

    /// A collection's first offset does not end a whole, non-empty offset table.
    #[error("first offset {0} does not end a whole offset table")]
    MisalignedOffsetTable(usize),

    /// An offset decreased, which would give a part negative length.
    #[error("offset {next} follows larger offset {previous}")]
    OffsetsNotIncreasing {
        /// The earlier offset.
        previous: usize,
        /// The later, smaller offset.
        next: usize,
    },

    /// An offset points past the end of the input.
    #[error("offset {offset} exceeds input length {length}")]
    OffsetOutOfBounds {
        /// The offset found.
        offset: usize,
        /// Length of the input.
        length: usize,
    },

    /// A collection holds more elements than its type allows.
    #[error("{actual} elements exceed the limit of {limit}")]
    TooManyElements {
        /// Maximum number of elements.
        limit: usize,
        /// Number of elements in the input.
        actual: usize,
    },

    /// A run of fixed-size elements does not divide into whole elements.
    #[error("{length} bytes do not divide into {element_size}-byte elements")]
    TrailingBytes {
        /// Size of one element.
        element_size: usize,
        /// Length of the run.
        length: usize,
    },

    /// A boolean byte is neither zero nor one.
    #[error("boolean byte {0:#04x} is not 0 or 1")]
    InvalidBoolean(u8),

    /// A bitlist lacks its length-marking sentinel bit.
    ///
    /// The input is empty or ends in a zero byte.
    #[error("bitlist of {length} bytes lacks its sentinel bit")]
    MissingSentinel {
        /// Length of the input in bytes.
        length: usize,
    },

    /// A bitvector sets padding bits beyond its length.
    ///
    /// Accepting them would give one value two encodings.
    #[error("bitvector of {length} bits sets padding bits in its last byte {last_byte:#04x}")]
    ExcessBits {
        /// Number of bits the type holds.
        length: usize,
        /// The last byte of the input, which holds the padding.
        last_byte: u8,
    },
}
