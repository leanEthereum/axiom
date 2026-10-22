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
    ///
    /// For a varint cut short, the bytes needed are a lower bound: one more than remain.
    #[error("message ends inside a field: {remaining} bytes left, at least {needed} needed")]
    Truncated {
        /// Bytes the field needs, or a lower bound on them.
        needed: u64,
        /// Bytes left in the input.
        remaining: usize,
    },

    /// A key uses a group or unassigned wire type.
    #[error("field {field} uses unsupported wire type {wire_type}")]
    InvalidWireType {
        /// Field number.
        field: u32,
        /// The wire type found.
        wire_type: u8,
    },

    /// A key carries field number zero or one above 2^29 - 1.
    #[error("field number {number} is outside 1..=536870911")]
    InvalidFieldNumber {
        /// The field number found.
        number: u64,
    },

    /// A known field arrives with a wire type its schema forbids.
    #[error("field {field} arrives with forbidden wire type {wire_type}")]
    UnexpectedWireType {
        /// Field number.
        field: u32,
        /// The wire type found.
        wire_type: u8,
    },

    /// A required field is absent.
    #[error("required field {0} is missing")]
    MissingField(u32),

    /// A string field holds bytes that are not UTF-8.
    #[error("field {field} is not UTF-8 after byte {valid_up_to}")]
    InvalidUtf8 {
        /// Field number.
        field: u32,
        /// Length of the longest valid UTF-8 prefix.
        valid_up_to: usize,
    },

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
