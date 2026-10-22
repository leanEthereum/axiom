//! Reasons a text fails to parse.

use std::fmt;

use thiserror::Error;

/// A text that is not a document of the supported YAML subset.
///
/// The parser stops at the first problem, so one input yields one error.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("line {line}, column {column}: {kind}")]
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

/// The rule a text broke.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A tab appears in the indentation of a line.
    ///
    /// YAML measures structure in spaces only.
    #[error("tab character in indentation")]
    TabIndentation,

    /// A line is indented in a way no enclosing block accepts.
    #[error("line does not fit the indentation of any enclosing block")]
    InvalidIndentation,

    /// A line inside a block mapping does not start with a key and a colon.
    #[error("expected a mapping key followed by a colon")]
    ExpectedKey,

    /// A key appears where only a value may stand, as in a value holding a colon.
    #[error("mapping value not allowed here")]
    UnexpectedMappingValue,

    /// A sequence entry indicator starts on the line of a key or of a value.
    #[error("sequence entry not allowed here")]
    UnexpectedBlockEntry,

    /// A mapping holds the same key twice.
    #[error("duplicate mapping key {0:?}")]
    DuplicateKey(String),

    /// A quoted scalar has no closing quote.
    #[error("quoted scalar has no closing quote")]
    UnterminatedQuote,

    /// A flow collection has no closing bracket or brace.
    #[error("flow collection has no closing bracket")]
    UnterminatedFlow,

    /// A backslash escape is not one that YAML defines.
    #[error("invalid escape sequence \\{0}")]
    InvalidEscape(char),

    /// A unicode escape names a value that is not a character.
    #[error("escape \\u{{{0:x}}} is not a unicode scalar value")]
    InvalidCodePoint(u32),

    /// A character that cannot start or continue the construct at hand.
    #[error("unexpected character {0:?}")]
    UnexpectedChar(char),

    /// Content follows a complete value on its line.
    #[error("unexpected content after a value")]
    TrailingContent,

    /// A document marker sits inside a quoted scalar or a flow collection.
    #[error("document marker inside a quoted scalar or flow collection")]
    UnexpectedDocumentMarker,

    /// Collections nest deeper than the parser allows.
    ///
    /// The bound keeps recursion, and so stack use, finite on hostile input.
    #[error("collections nest too deeply")]
    TooDeep,

    /// A valid YAML construct outside the supported subset.
    #[error("{0} are not supported")]
    Unsupported(Unsupported),
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
