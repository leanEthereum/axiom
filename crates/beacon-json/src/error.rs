//! Errors of the JSON codec, located by a member path.

use std::fmt::Write;

use axiom_json::{HexError, Json};
use axiom_ssz::DecodeError;
use axiom_types::ForkName;
use thiserror::Error;

use crate::DecimalError;

/// A JSON value that does not map onto a consensus container.
///
/// The path locates the value, as in `body.attestations[3].data.slot`.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{}{kind}", self.location())]
pub struct ApiJsonError {
    /// Member names and indices from the outside in.
    path: Vec<PathSegment>,
    /// What is wrong at that location.
    kind: ApiJsonErrorKind,
}

/// One step into a JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathSegment {
    /// An object member.
    Member(&'static str),
    /// An array position.
    Index(usize),
}

impl ApiJsonError {
    /// An error at the current value.
    #[must_use]
    pub const fn new(kind: ApiJsonErrorKind) -> Self {
        Self {
            path: Vec::new(),
            kind,
        }
    }

    /// The error for a value of the wrong JSON type.
    pub(crate) const fn wrong_type(expected: &'static str, found: &Json) -> Self {
        Self::new(ApiJsonErrorKind::Type {
            expected,
            found: found.kind(),
        })
    }

    /// The error for a malformed or out-of-range decimal string.
    pub(crate) const fn decimal(error: DecimalError) -> Self {
        Self::new(ApiJsonErrorKind::Decimal(error))
    }

    /// The error for a fork that has no container of a kind.
    #[must_use]
    pub const fn absent(fork: ForkName, container: &'static str) -> Self {
        Self::new(ApiJsonErrorKind::AbsentInFork { fork, container })
    }

    /// The error for a malformed hex string.
    pub(crate) const fn hex(error: HexError) -> Self {
        match error {
            // Hex of the wrong size is a length problem, not an encoding one.
            HexError::WrongLength { expected, actual } => {
                Self::new(ApiJsonErrorKind::WrongLength { expected, actual })
            }
            other => Self::new(ApiJsonErrorKind::Hex(other)),
        }
    }

    /// Places the error inside an object member.
    #[must_use]
    pub fn in_member(mut self, name: &'static str) -> Self {
        // Errors bubble outward, so each enclosing step goes in front.
        self.path.insert(0, PathSegment::Member(name));
        self
    }

    /// Places the error inside an array element.
    #[must_use]
    pub fn at_index(mut self, index: usize) -> Self {
        self.path.insert(0, PathSegment::Index(index));
        self
    }

    /// What is wrong.
    #[must_use]
    pub const fn kind(&self) -> &ApiJsonErrorKind {
        &self.kind
    }

    /// The location, written as a member path such as `body.attestations[3].data.slot`.
    ///
    /// The outermost value has the empty path.
    #[must_use]
    pub fn path(&self) -> String {
        let mut out = String::new();
        for segment in &self.path {
            match segment {
                // Members after the first are joined with a dot.
                PathSegment::Member(name) => {
                    if !out.is_empty() {
                        out.push('.');
                    }
                    out.push_str(name);
                }
                PathSegment::Index(index) => {
                    let _ = write!(out, "[{index}]");
                }
            }
        }
        out
    }

    /// The location with its separator, or nothing for the outermost value.
    fn location(&self) -> String {
        if self.path.is_empty() {
            String::new()
        } else {
            format!("{}: ", self.path())
        }
    }
}

impl From<ApiJsonErrorKind> for ApiJsonError {
    fn from(kind: ApiJsonErrorKind) -> Self {
        Self::new(kind)
    }
}

/// The rule a JSON value broke.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ApiJsonErrorKind {
    /// A required member is absent or null.
    #[error("required value is missing")]
    Missing,

    /// The value has the wrong JSON type.
    #[error("expected {expected}, found a JSON {found}")]
    Type {
        /// What the container requires, such as a decimal string.
        expected: &'static str,
        /// The JSON type found.
        found: &'static str,
    },

    /// A decimal string is malformed or out of range.
    #[error("{0}")]
    Decimal(DecimalError),

    /// A hex string is malformed.
    #[error("{0}")]
    Hex(HexError),

    /// A fixed-size value has the wrong length.
    #[error("length {actual}, expected {expected}")]
    WrongLength {
        /// The length the type requires.
        expected: usize,
        /// The length found.
        actual: usize,
    },

    /// A list holds more items or bytes than its type allows.
    #[error("{actual} items exceed the limit {limit}")]
    TooLong {
        /// The most the type allows.
        limit: usize,
        /// The count found.
        actual: usize,
    },

    /// The bytes of a bitlist or bitvector are not a canonical SSZ encoding.
    #[error("{0}")]
    Bits(DecodeError),

    /// The fork has no container of the requested kind.
    #[error("the {fork} fork has no {container}")]
    AbsentInFork {
        /// The fork the caller named.
        fork: ForkName,
        /// The kind of container, such as a blinded block.
        container: &'static str,
    },
}

impl ApiJsonErrorKind {
    /// Checks a variable count against the most its type allows.
    pub(crate) const fn check_limit(limit: usize, actual: usize) -> Result<(), Self> {
        if actual > limit {
            Err(Self::TooLong { limit, actual })
        } else {
            Ok(())
        }
    }

    /// Checks a count against the exact length its type requires.
    pub(crate) const fn check_length(expected: usize, actual: usize) -> Result<(), Self> {
        if actual == expected {
            Ok(())
        } else {
            Err(Self::WrongLength { expected, actual })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_prefixes_the_path() {
        // A slot written as a number, three levels deep in a block body.
        let error = ApiJsonError::wrong_type("a decimal string", &Json::from(7_u64))
            .in_member("slot")
            .in_member("data")
            .at_index(3)
            .in_member("attestations")
            .in_member("body");

        assert_eq!(error.path(), "body.attestations[3].data.slot");
        assert_eq!(
            error.to_string(),
            "body.attestations[3].data.slot: expected a decimal string, found a JSON number"
        );
    }

    #[test]
    fn display_of_the_outermost_value_has_no_path() {
        // A missing value at the top has nothing to locate.
        let error = ApiJsonError::new(ApiJsonErrorKind::Missing);
        assert_eq!(error.path(), "");
        assert_eq!(error.to_string(), "required value is missing");
    }

    #[test]
    fn a_wrong_hex_length_is_a_length_error() {
        // 31 bytes where a root holds 32.
        let error = ApiJsonError::hex(HexError::WrongLength {
            expected: 32,
            actual: 31,
        });
        assert_eq!(
            error,
            ApiJsonError::new(ApiJsonErrorKind::WrongLength {
                expected: 32,
                actual: 31
            })
        );

        // Any other hex failure stays a hex error.
        assert_eq!(
            ApiJsonError::hex(HexError::MissingPrefix),
            ApiJsonError::new(ApiJsonErrorKind::Hex(HexError::MissingPrefix))
        );
    }
}
