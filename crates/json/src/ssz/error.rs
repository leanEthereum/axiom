//! Why a JSON value is not the JSON form of an SSZ value.

use axiom_ssz::DecodeError;
use thiserror::Error;

use crate::HexError;

/// A JSON value that does not follow an SSZ schema.
///
/// Each variant names the place it strays, as a path such as `$.message.body.deposits[2]`.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SszJsonError {
    /// The value has the wrong JSON kind.
    #[error("{path}: expected {expected}, found {found}")]
    WrongKind {
        /// Where the value sits.
        path: String,
        /// What the schema asks for.
        expected: &'static str,
        /// The JSON kind found.
        found: &'static str,
    },

    /// An integer is malformed or out of range for its width.
    #[error("{path}: {text} is not a {bits}-bit unsigned integer")]
    InvalidUint {
        /// Where the value sits.
        path: String,
        /// The text found.
        text: String,
        /// The integer's width in bits.
        bits: usize,
    },

    /// Hex bytes are malformed.
    #[error("{path}: {source}")]
    InvalidHex {
        /// Where the value sits.
        path: String,
        /// What is wrong with the hex.
        source: HexError,
    },

    /// A fixed-length value has the wrong length.
    #[error("{path}: expected {expected} items, found {actual}")]
    WrongLength {
        /// Where the value sits.
        path: String,
        /// The length the type fixes.
        expected: usize,
        /// The length found.
        actual: usize,
    },

    /// A bounded value is longer than its limit.
    #[error("{path}: {actual} items exceed the limit of {limit}")]
    TooLong {
        /// Where the value sits.
        path: String,
        /// The most items allowed.
        limit: usize,
        /// The number of items found.
        actual: usize,
    },

    /// A container lacks a field.
    #[error("{path}: missing field {field}")]
    MissingField {
        /// Where the container sits.
        path: String,
        /// The field's name.
        field: &'static str,
    },

    /// A container has a member its type does not declare.
    #[error("{path}: unknown field {field}")]
    UnknownField {
        /// Where the container sits.
        path: String,
        /// The member's name.
        field: String,
    },

    /// A union names a selector it does not declare.
    #[error("{path}: unknown union selector {selector}")]
    UnknownSelector {
        /// Where the union sits.
        path: String,
        /// The selector found.
        selector: String,
    },

    /// The bytes the JSON describes break an invariant of the SSZ type.
    #[error("invalid value: {0}")]
    Decode(#[from] DecodeError),
}
