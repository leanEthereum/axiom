//! Reasons a text fails to parse.

use std::{error::Error, fmt};

/// A text that is not a document of the supported YAML subset.
///
/// The parser stops at the first problem, so one input yields one error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// Line of the problem, counted from 1.
    pub(crate) line: usize,
    /// Column of the problem in characters, counted from 1.
    pub(crate) column: usize,
    /// What went wrong.
    pub(crate) kind: ErrorKind,
}

impl ParseError {
    /// Line of the problem, counted from 1.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// Column of the problem in characters, counted from 1.
    #[must_use]
    pub const fn column(&self) -> usize {
        self.column
    }

    /// What went wrong.
    #[must_use]
    pub const fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {}, column {}: {}",
            self.line, self.column, self.kind
        )
    }
}

impl Error for ParseError {}

/// The rule a text broke.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A tab appears in the indentation of a line.
    ///
    /// YAML measures structure in spaces only.
    TabIndentation,

    /// A line is indented in a way no enclosing block accepts.
    InvalidIndentation,

    /// A line inside a block mapping does not start with a key and a colon.
    ExpectedKey,

    /// A key appears where only a value may stand, as in a value holding a colon.
    UnexpectedMappingValue,

    /// A sequence entry indicator starts on the line of a key or of a value.
    UnexpectedBlockEntry,

    /// A mapping holds the same key twice.
    DuplicateKey(String),

    /// A quoted scalar has no closing quote.
    UnterminatedQuote,

    /// A flow collection has no closing bracket or brace.
    UnterminatedFlow,

    /// A backslash escape is not one that YAML defines.
    InvalidEscape(char),

    /// A unicode escape names a value that is not a character.
    InvalidCodePoint(u32),

    /// A character that cannot start or continue the construct at hand.
    UnexpectedChar(char),

    /// Content follows a complete value on its line.
    TrailingContent,

    /// A document marker sits inside a quoted scalar or a flow collection.
    UnexpectedDocumentMarker,

    /// Collections nest deeper than the parser allows.
    ///
    /// The bound keeps recursion, and so stack use, finite on hostile input.
    TooDeep,

    /// A valid YAML construct outside the supported subset.
    Unsupported(Unsupported),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TabIndentation => f.write_str("tab character in indentation"),
            Self::InvalidIndentation => {
                f.write_str("line does not fit the indentation of any enclosing block")
            }
            Self::ExpectedKey => f.write_str("expected a mapping key followed by a colon"),
            Self::UnexpectedMappingValue => f.write_str("mapping value not allowed here"),
            Self::UnexpectedBlockEntry => f.write_str("sequence entry not allowed here"),
            Self::DuplicateKey(key) => write!(f, "duplicate mapping key {key:?}"),
            Self::UnterminatedQuote => f.write_str("quoted scalar has no closing quote"),
            Self::UnterminatedFlow => f.write_str("flow collection has no closing bracket"),
            Self::InvalidEscape(c) => write!(f, "invalid escape sequence \\{c}"),
            Self::InvalidCodePoint(value) => {
                write!(f, "escape \\u{{{value:x}}} is not a unicode scalar value")
            }
            Self::UnexpectedChar(c) => write!(f, "unexpected character {c:?}"),
            Self::TrailingContent => f.write_str("unexpected content after a value"),
            Self::UnexpectedDocumentMarker => {
                f.write_str("document marker inside a quoted scalar or flow collection")
            }
            Self::TooDeep => f.write_str("collections nest too deeply"),
            Self::Unsupported(feature) => write!(f, "{feature} are not supported"),
        }
    }
}

/// A YAML feature this parser rejects rather than risks misreading.
///
/// None of these occur in consensus configs or test vectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Unsupported {
    /// An anchor, written `&name`.
    Anchor,
    /// An alias, written `*name`.
    Alias,
    /// A tag, written with `!`.
    Tag,
    /// A literal or folded block scalar, written `|` or `>`.
    BlockScalar,
    /// A directive line, written with `%`.
    Directive,
    /// An explicit key, written `? `.
    ComplexKey,
    /// More than one document in one text.
    MultipleDocuments,
    /// A single-pair mapping inside a flow sequence, as in `[a: 1]`.
    FlowPair,
    /// A collection used as a mapping key.
    CollectionKey,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Anchor => "anchors",
            Self::Alias => "aliases",
            Self::Tag => "tags",
            Self::BlockScalar => "block scalars",
            Self::Directive => "directives",
            Self::ComplexKey => "explicit keys",
            Self::MultipleDocuments => "multiple documents",
            Self::FlowPair => "pairs inside flow sequences",
            Self::CollectionKey => "collection keys",
        })
    }
}
