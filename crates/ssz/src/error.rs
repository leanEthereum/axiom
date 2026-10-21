//! Reasons a byte string fails to decode.

use std::{error::Error, fmt};

/// A byte string that is not the encoding of any value of the expected type.
///
/// Every variant names the rule the input broke.
/// Decoders reject at the first broken rule, so one input yields one error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// A fixed-size value received the wrong number of bytes.
    InvalidLength {
        /// Length the type requires.
        expected: usize,
        /// Length the input had.
        actual: usize,
    },

    /// The input ended before a fixed-size part or an offset was complete.
    TooShort {
        /// Minimum length the type requires.
        minimum: usize,
        /// Length the input had.
        actual: usize,
    },

    /// The first offset does not point right past the fixed-size part.
    ///
    /// Any other value would leave unread bytes or overlap the fixed part.
    FirstOffsetMismatch {
        /// Length of the fixed-size part.
        expected: usize,
        /// Offset found in the input.
        actual: usize,
    },

    /// A collection's first offset does not end a whole, non-empty offset table.
    MisalignedOffsetTable(usize),

    /// An offset decreased, which would give a part negative length.
    OffsetsNotIncreasing {
        /// The earlier offset.
        previous: usize,
        /// The later, smaller offset.
        next: usize,
    },

    /// An offset points past the end of the input.
    OffsetOutOfBounds {
        /// The offset found.
        offset: usize,
        /// Length of the input.
        length: usize,
    },

    /// A collection holds more elements than its type allows.
    TooManyElements {
        /// Maximum number of elements.
        limit: usize,
        /// Number of elements in the input.
        actual: usize,
    },

    /// A run of fixed-size elements does not divide into whole elements.
    TrailingBytes {
        /// Size of one element.
        element_size: usize,
        /// Length of the run.
        length: usize,
    },

    /// A boolean byte is neither zero nor one.
    InvalidBoolean(u8),

    /// A bitlist lacks its length-marking sentinel bit.
    MissingSentinel,

    /// A bitvector sets padding bits beyond its length.
    ///
    /// Accepting them would give one value two encodings.
    ExcessBits,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
            Self::TooShort { minimum, actual } => {
                write!(f, "expected at least {minimum} bytes, got {actual}")
            }
            Self::FirstOffsetMismatch { expected, actual } => {
                write!(f, "first offset is {actual}, fixed part ends at {expected}")
            }
            Self::MisalignedOffsetTable(offset) => {
                write!(f, "first offset {offset} does not end a whole offset table")
            }
            Self::OffsetsNotIncreasing { previous, next } => {
                write!(f, "offset {next} follows larger offset {previous}")
            }
            Self::OffsetOutOfBounds { offset, length } => {
                write!(f, "offset {offset} exceeds input length {length}")
            }
            Self::TooManyElements { limit, actual } => {
                write!(f, "{actual} elements exceed the limit of {limit}")
            }
            Self::TrailingBytes {
                element_size,
                length,
            } => write!(
                f,
                "{length} bytes do not divide into {element_size}-byte elements"
            ),
            Self::InvalidBoolean(byte) => write!(f, "boolean byte {byte:#04x} is not 0 or 1"),
            Self::MissingSentinel => f.write_str("bitlist lacks its sentinel bit"),
            Self::ExcessBits => f.write_str("bitvector sets bits beyond its length"),
        }
    }
}

impl Error for DecodeError {}
