//! Reasons a byte string is not the DER encoding of the expected value.

use thiserror::Error;

/// A byte string that is not the DER encoding of the expected value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DerError {
    /// The input ends inside a value, or before a required one.
    #[error("input ends early: {needed} bytes needed, {available} available")]
    Truncated {
        /// Bytes the value needs.
        needed: usize,
        /// Bytes left in the input.
        available: usize,
    },

    /// A value carries another tag than the one the structure requires.
    #[error("expected tag {expected:#04x}, found {found:#04x}")]
    UnexpectedTag {
        /// The tag the structure requires.
        expected: u8,
        /// The tag found.
        found: u8,
    },

    /// A tag uses the multi-byte high tag number form.
    #[error("tag {0:#04x} uses the high tag number form")]
    HighTagNumber(u8),

    /// A length uses the indefinite form 0x80, which DER forbids.
    #[error("indefinite length")]
    IndefiniteLength,

    /// A length uses more bytes than it needs.
    #[error("length {length} is not in its shortest form")]
    NonMinimalLength {
        /// The length decoded.
        length: usize,
    },

    /// A long-form length announces more length bytes than any certificate needs.
    #[error("length of {count} bytes exceeds the limit of {max}")]
    LengthTooLong {
        /// Length bytes announced.
        count: usize,
        /// Most length bytes accepted.
        max: usize,
    },

    /// Bytes remain after the last value of a container.
    #[error("{count} trailing bytes after the last value")]
    TrailingBytes {
        /// Bytes left over.
        count: usize,
    },

    /// An INTEGER has no content bytes.
    #[error("empty integer")]
    EmptyInteger,

    /// An INTEGER has a redundant leading 0x00 or 0xff byte.
    #[error("integer is not in its shortest form")]
    NonMinimalInteger,

    /// An INTEGER that must be non-negative has its sign bit set.
    #[error("integer is negative")]
    NegativeInteger,

    /// An INTEGER has more magnitude bytes than its field allows.
    #[error("integer of {length} bytes exceeds {max}")]
    IntegerTooLong {
        /// Magnitude bytes found.
        length: usize,
        /// Most magnitude bytes allowed.
        max: usize,
    },

    /// A BOOLEAN is not one byte of 0x00 or 0xff.
    #[error("boolean content is not a single 0x00 or 0xff")]
    InvalidBoolean,

    /// A BIT STRING is empty or has unused bits, where a whole number of bytes is required.
    #[error("bit string does not hold whole bytes")]
    PartialBitString,

    /// A time value is not of the form YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ, or names no real instant.
    #[error("malformed time value")]
    InvalidTime,
}
