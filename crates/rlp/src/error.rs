//! Reasons a byte string is refused as RLP.

use std::{error::Error, fmt};

/// Input that is not the canonical RLP encoding of the expected shape.
///
/// Decoding stops at the first broken rule, so one input yields one error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RlpError {
    /// The input ends inside a header or a payload.
    UnexpectedEnd,

    /// A single byte below `0x80` is wrapped in a string header.
    ///
    /// Such a byte must encode as itself, per the Yellow Paper, appendix B.
    NonCanonicalSingleByte,

    /// A length uses the long form for a payload under 56 bytes.
    NonCanonicalLength,

    /// A long-form length starts with a zero byte.
    LeadingZeroInLength,

    /// A long-form length does not fit the address space.
    LengthOverflow,

    /// An integer payload starts with a zero byte.
    ///
    /// Integers are minimal big-endian, so zero is the empty string.
    LeadingZeroInInteger,

    /// An integer payload is wider than the target type.
    IntegerOverflow {
        /// Widest payload the target accepts, in bytes.
        max: usize,
        /// Bytes in the payload.
        found: usize,
    },

    /// A list was found where a string was expected.
    ExpectedString,

    /// A string was found where a list was expected.
    ExpectedList,

    /// A string has the wrong length for a fixed-size target.
    WrongLength {
        /// Length the target needs.
        expected: usize,
        /// Length of the payload.
        found: usize,
    },

    /// Bytes remain after the last expected item.
    TrailingBytes,

    /// Lists nest deeper than the decoder allows.
    TooDeep,
}

impl fmt::Display for RlpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd => f.write_str("input ends inside an item"),
            Self::NonCanonicalSingleByte => {
                f.write_str("single byte below 0x80 wrapped in a string header")
            }
            Self::NonCanonicalLength => f.write_str("long-form length for a short payload"),
            Self::LeadingZeroInLength => f.write_str("long-form length starts with zero"),
            Self::LengthOverflow => f.write_str("length does not fit the address space"),
            Self::LeadingZeroInInteger => f.write_str("integer starts with a zero byte"),
            Self::IntegerOverflow { max, found } => {
                write!(f, "integer of {found} bytes exceeds {max} bytes")
            }
            Self::ExpectedString => f.write_str("expected a string, found a list"),
            Self::ExpectedList => f.write_str("expected a list, found a string"),
            Self::WrongLength { expected, found } => {
                write!(f, "expected {expected} bytes, found {found}")
            }
            Self::TrailingBytes => f.write_str("bytes remain after the last item"),
            Self::TooDeep => f.write_str("lists nest too deeply"),
        }
    }
}

impl Error for RlpError {}
