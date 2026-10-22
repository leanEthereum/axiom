//! Reasons a text fails to parse.

use thiserror::Error;

/// A text that is not one JSON value within the limits.
///
/// The parser stops at the first problem, so one input yields one error.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("byte {offset}: {kind}")]
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

/// The rule a text broke.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The text ends before the value does.
    #[error("unexpected end of input")]
    UnexpectedEnd,

    /// A byte that cannot start or continue the construct at hand.
    #[error("unexpected byte 0x{0:02x}")]
    UnexpectedByte(u8),

    /// A string holds bytes that are not UTF-8.
    #[error("string is not valid UTF-8")]
    InvalidUtf8,

    /// A string holds a raw control character below 0x20.
    ///
    /// RFC 8259 section 7 requires these to be escaped.
    #[error("unescaped control character 0x{0:02x} in string")]
    ControlCharacter(u8),

    /// A backslash is followed by a byte that names no escape.
    #[error("invalid escape byte 0x{0:02x}")]
    InvalidEscape(u8),

    /// A unicode escape holds a byte that is not a hex digit.
    ///
    /// The value is the offending byte.
    #[error("unicode escape holds non-hex byte 0x{0:02x}")]
    InvalidUnicodeEscape(u8),

    /// A unicode escape names half of a surrogate pair without the other half.
    #[error("lone surrogate \\u{0:04x}")]
    LoneSurrogate(u16),

    /// A number breaks the grammar of RFC 8259 section 6.
    #[error("malformed number")]
    InvalidNumber,

    /// An object names the same member twice.
    #[error("duplicate object member {0:?}")]
    DuplicateKey(String),

    /// Something other than whitespace follows the value.
    #[error("unexpected content after the value")]
    TrailingCharacters,

    /// Arrays and objects nest deeper than the limit.
    #[error("arrays and objects nest deeper than {limit} levels")]
    TooDeep {
        /// Deepest nesting the limits accept.
        limit: usize,
    },

    /// The text is longer than the limit.
    #[error("input of {length} bytes exceeds the limit of {limit}")]
    TooLarge {
        /// Length of the text in bytes.
        length: usize,
        /// Longest text the limits accept, in bytes.
        limit: usize,
    },
}
