//! Reasons a byte string is not the encoding of the expected message.

use thiserror::Error;

use crate::varint::VarintError;

/// A byte string that is not the encoding of the expected message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProtobufError {
    /// A key, length, or value varint is malformed.
    #[error("malformed varint: {0}")]
    Varint(#[from] VarintError),

    /// The input ends inside a field.
    #[error("message ends inside a field")]
    Truncated,

    /// A key uses a group or unassigned wire type.
    #[error("unsupported wire type {0}")]
    InvalidWireType(u8),

    /// A key carries field number zero or one above 2^29 - 1.
    #[error("field number out of range")]
    InvalidFieldNumber,

    /// A known field arrives with a wire type its schema forbids.
    #[error("field {0} has the wrong wire type")]
    UnexpectedWireType(u32),

    /// A required field is absent.
    #[error("required field {0} is missing")]
    MissingField(u32),

    /// A string field holds bytes that are not UTF-8.
    #[error("field {0} is not valid UTF-8")]
    InvalidUtf8(u32),

    /// An enum field holds a value outside the schema.
    #[error("field {field} holds unknown enum value {value}")]
    InvalidEnum {
        /// Field number.
        field: u32,
        /// The value found.
        value: u64,
    },

    /// A length-prefixed frame declares more bytes than the reader accepts.
    #[error("frame of {len} bytes exceeds the limit of {max}")]
    FrameTooLarge {
        /// Declared length.
        len: usize,
        /// Largest length accepted.
        max: usize,
    },

    /// A repeated field holds more elements than the reader accepts.
    #[error("field {field} repeats more than {max} times")]
    TooManyElements {
        /// Field number.
        field: u32,
        /// Largest count accepted.
        max: usize,
    },
}
