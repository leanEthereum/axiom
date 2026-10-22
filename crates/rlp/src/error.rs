//! Reasons a byte string is refused as RLP.

use thiserror::Error;

/// Input that is not the canonical RLP encoding of the expected shape.
///
/// Decoding stops at the first broken rule, so one input yields one error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RlpError {
    /// The input ends inside a header or a payload.
    #[error("input ends inside an item")]
    UnexpectedEnd,

    /// A single byte below `0x80` is wrapped in a string header.
    ///
    /// Such a byte must encode as itself, per the Yellow Paper, appendix B.
    #[error("single byte below 0x80 wrapped in a string header")]
    NonCanonicalSingleByte,

    /// A length uses the long form for a payload under 56 bytes.
    #[error("long-form length for a short payload")]
    NonCanonicalLength,

    /// A long-form length starts with a zero byte.
    #[error("long-form length starts with zero")]
    LeadingZeroInLength,

    /// A long-form length does not fit the address space.
    #[error("length does not fit the address space")]
    LengthOverflow,

    /// An integer payload starts with a zero byte.
    ///
    /// Integers are minimal big-endian, so zero is the empty string.
    #[error("integer starts with a zero byte")]
    LeadingZeroInInteger,

    /// An integer payload is wider than the target type.
    #[error("integer of {found} bytes exceeds {max} bytes")]
    IntegerOverflow {
        /// Widest payload the target accepts, in bytes.
        max: usize,
        /// Bytes in the payload.
        found: usize,
    },

    /// A list was found where a string was expected.
    #[error("expected a string, found a list")]
    ExpectedString,

    /// A string was found where a list was expected.
    #[error("expected a list, found a string")]
    ExpectedList,

    /// A string has the wrong length for a fixed-size target.
    #[error("expected {expected} bytes, found {found}")]
    WrongLength {
        /// Length the target needs.
        expected: usize,
        /// Length of the payload.
        found: usize,
    },

    /// Bytes remain after the last expected item.
    #[error("bytes remain after the last item")]
    TrailingBytes,

    /// Lists nest deeper than the decoder allows.
    #[error("lists nest too deeply")]
    TooDeep,
}
