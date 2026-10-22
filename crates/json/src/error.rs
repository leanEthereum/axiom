//! Reasons a text fails to parse.

use std::{error::Error, fmt};

/// A text that is not one JSON value within the limits.
///
/// The parser stops at the first problem, so one input yields one error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset of the problem, counted from 0.
    pub(crate) offset: usize,
    /// What went wrong.
    pub(crate) kind: ErrorKind,
}

impl ParseError {
    /// Byte offset of the problem, counted from 0.
    ///
    /// For a truncated text it equals the text's length.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// What went wrong.
    #[must_use]
    pub const fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "byte {}: {}", self.offset, self.kind)
    }
}

impl Error for ParseError {}

/// The rule a text broke.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The text ends before the value does.
    UnexpectedEnd,

    /// A byte that cannot start or continue the construct at hand.
    UnexpectedByte(u8),

    /// A string holds bytes that are not UTF-8.
    InvalidUtf8,

    /// A string holds a raw control character below 0x20.
    ///
    /// RFC 8259 section 7 requires these to be escaped.
    ControlCharacter(u8),

    /// A backslash is followed by a byte that names no escape.
    InvalidEscape(u8),

    /// A unicode escape is not four hex digits.
    InvalidUnicodeEscape,

    /// A unicode escape names half of a surrogate pair without the other half.
    LoneSurrogate(u16),

    /// A number breaks the grammar of RFC 8259 section 6.
    InvalidNumber,

    /// An object names the same member twice.
    DuplicateKey(String),

    /// Something other than whitespace follows the value.
    TrailingCharacters,

    /// Arrays and objects nest deeper than the limit.
    TooDeep,

    /// The text is longer than the limit.
    TooLarge,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd => f.write_str("unexpected end of input"),
            Self::UnexpectedByte(byte) => write!(f, "unexpected byte 0x{byte:02x}"),
            Self::InvalidUtf8 => f.write_str("string is not valid UTF-8"),
            Self::ControlCharacter(byte) => {
                write!(f, "unescaped control character 0x{byte:02x} in string")
            }
            Self::InvalidEscape(byte) => write!(f, "invalid escape byte 0x{byte:02x}"),
            Self::InvalidUnicodeEscape => f.write_str("unicode escape needs four hex digits"),
            Self::LoneSurrogate(unit) => write!(f, "lone surrogate \\u{unit:04x}"),
            Self::InvalidNumber => f.write_str("malformed number"),
            Self::DuplicateKey(key) => write!(f, "duplicate object member {key:?}"),
            Self::TrailingCharacters => f.write_str("unexpected content after the value"),
            Self::TooDeep => f.write_str("arrays and objects nest too deeply"),
            Self::TooLarge => f.write_str("input exceeds the size limit"),
        }
    }
}
