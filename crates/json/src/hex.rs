//! Hex digits and the errors of the Ethereum hex encodings.

use std::{error::Error, fmt};

/// Lowercase digits, the form every execution client emits.
pub(crate) const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The value of one hex digit, in either case.
///
/// The engine API's encoding rules allow either case on input.
/// Encoders here emit lowercase only, as every execution client does.
pub(crate) const fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The digits after the mandatory 0x prefix.
pub(crate) fn strip_prefix(text: &str) -> Result<&[u8], HexError> {
    // Only a lowercase x is the Ethereum prefix; "0X" is rejected.
    text.as_bytes()
        .strip_prefix(b"0x")
        .ok_or(HexError::MissingPrefix)
}

/// A string that is not a valid QUANTITY or DATA.
///
/// Offsets count bytes from the start of the string, prefix included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HexError {
    /// The string does not start with 0x.
    MissingPrefix,

    /// A QUANTITY has no digits after the prefix.
    Empty,

    /// A QUANTITY has a zero before its first significant digit.
    LeadingZero,

    /// A DATA has an odd number of digits, so its last byte is half missing.
    OddLength,

    /// A byte that is not a hex digit.
    InvalidDigit {
        /// Byte offset of the offending character.
        offset: usize,
    },

    /// A QUANTITY exceeds the width of its integer type.
    Overflow,

    /// A DATA decodes to a different number of bytes than its type holds.
    WrongLength {
        /// Bytes the type holds.
        expected: usize,
        /// Bytes the string encodes.
        actual: usize,
    },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => f.write_str("hex string lacks the 0x prefix"),
            Self::Empty => f.write_str("quantity has no digits"),
            Self::LeadingZero => f.write_str("quantity has a leading zero"),
            Self::OddLength => f.write_str("data has an odd number of hex digits"),
            Self::InvalidDigit { offset } => write!(f, "invalid hex digit at byte {offset}"),
            Self::Overflow => f.write_str("quantity overflows its integer type"),
            Self::WrongLength { expected, actual } => {
                write!(f, "data holds {actual} bytes, expected {expected}")
            }
        }
    }
}

impl Error for HexError {}
