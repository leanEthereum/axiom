//! Why a JSON value is not the container it should be.

use axiom_json::{HexError, Json};
use axiom_ssz::DecodeError;
use thiserror::Error;

/// A JSON value that does not read as the expected value.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum JsonError {
    /// The value has the wrong JSON type.
    #[error("expected {expected}, found {found}")]
    Type {
        /// The JSON type required.
        expected: &'static str,
        /// The JSON type found.
        found: &'static str,
    },
    /// An object lacks a required member.
    #[error("missing member {0}")]
    Missing(&'static str),
    /// A member's value is wrong.
    #[error("member {name}: {source}")]
    Member {
        /// The member's name.
        name: &'static str,
        /// What is wrong with its value.
        #[source]
        source: Box<Self>,
    },
    /// An array item is wrong.
    #[error("item {index}: {source}")]
    Item {
        /// The item's position.
        index: usize,
        /// What is wrong with it.
        #[source]
        source: Box<Self>,
    },
    /// A string is not a decimal integer that fits.
    #[error("{text:?} is not a decimal integer of at most {bits} bits")]
    Number {
        /// The text found.
        text: String,
        /// Width of the integer.
        bits: u32,
    },
    /// A string is not valid hex of the right length.
    #[error("invalid hex: {0}")]
    Hex(#[from] HexError),
    /// Hex bytes do not decode as the SSZ value they carry.
    #[error("invalid SSZ bytes: {0}")]
    Ssz(#[from] DecodeError),
    /// A list holds more items than its bound.
    #[error("{len} items exceed the bound of {max}")]
    TooLong {
        /// Items found.
        len: usize,
        /// Most items allowed.
        max: usize,
    },
    /// A string names no known value.
    #[error("unknown value {0:?}")]
    Unknown(String),
}

impl JsonError {
    /// A value of the wrong JSON type.
    pub(crate) const fn mismatch(expected: &'static str, json: &Json) -> Self {
        Self::Type {
            expected,
            found: json.kind(),
        }
    }
}
