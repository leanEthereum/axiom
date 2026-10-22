//! Errors of the engine API client.

use std::fmt::Write;

use axiom_http::{HttpError, StatusCode};
use axiom_json::{HexError, ParseError};
use axiom_ssz::DecodeError;
use thiserror::Error;

use crate::RpcError;

/// A call to the execution engine that did not produce a typed result.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EngineError {
    /// The HTTP exchange failed: connection, timeout, or framing.
    #[error("engine transport: {0}")]
    Http(#[from] HttpError),

    /// The engine answered with a status other than 200.
    ///
    /// A 401 or 403 means it rejected the token: check the shared secret and the clocks.
    #[error("engine replied with HTTP status {0}")]
    Status(StatusCode),

    /// The response body is not JSON.
    #[error("engine response is not JSON: {0}")]
    Json(#[source] ParseError),

    /// The response is JSON but not a JSON-RPC 2.0 response to this request.
    #[error("engine response is not JSON-RPC: {0}")]
    Envelope(#[from] EnvelopeError),

    /// The engine returned a JSON-RPC error object.
    #[error("engine error: {0}")]
    Rpc(#[from] RpcError),

    /// The result does not map onto the expected structure.
    #[error("engine result is malformed: {0}")]
    Wire(#[from] WireError),
}

/// A response that breaks the JSON-RPC 2.0 envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The response is not an object.
    #[error("response is not an object")]
    NotAnObject,

    /// The version member is missing or not "2.0".
    #[error("jsonrpc member is not \"2.0\"")]
    WrongVersion,

    /// The id does not echo the request's id.
    #[error("id does not match the request")]
    IdMismatch,

    /// Neither or both of the result and error members are present.
    #[error("response needs exactly one of result and error")]
    ResultOrError,

    /// The error member lacks an integer code or a string message.
    #[error("error object lacks a code or message")]
    MalformedError,
}

/// A JSON value that does not map onto an engine API structure.
///
/// The path locates the value, as in `executionPayload.withdrawals[2].amount`.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{}{kind}", self.location())]
pub struct WireError {
    /// Member names and indices from the outside in.
    path: Vec<PathSegment>,
    /// What is wrong at that location.
    kind: WireErrorKind,
}

/// One step into a JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathSegment {
    /// An object member.
    Member(&'static str),
    /// An array position.
    Index(usize),
}

impl WireError {
    /// An error at the current value.
    #[must_use]
    pub const fn new(kind: WireErrorKind) -> Self {
        Self {
            path: Vec::new(),
            kind,
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
    pub const fn kind(&self) -> &WireErrorKind {
        &self.kind
    }

    /// The location, written as a member path such as `blobsBundle.proofs[3]`.
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

impl From<WireErrorKind> for WireError {
    fn from(kind: WireErrorKind) -> Self {
        Self::new(kind)
    }
}

/// The rule a JSON value broke.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum WireErrorKind {
    /// A required member is absent or null.
    #[error("required value is missing")]
    Missing,

    /// The value has the wrong JSON type.
    #[error("expected {expected}, found {found}")]
    Type {
        /// The JSON type the structure requires.
        expected: &'static str,
        /// The JSON type found.
        found: &'static str,
    },

    /// A QUANTITY or DATA string is malformed.
    #[error("{0}")]
    Hex(HexError),

    /// A list holds more items or bytes than its type allows.
    #[error("{actual} items exceed the limit {limit}")]
    TooLong {
        /// The most the type allows.
        limit: usize,
        /// The count found.
        actual: usize,
    },

    /// A fixed-size value has the wrong length.
    #[error("length {actual}, expected {expected}")]
    WrongLength {
        /// The length the type requires.
        expected: usize,
        /// The length found.
        actual: usize,
    },

    /// A payload status string outside the five the spec defines.
    #[error("unknown payload status {0:?}")]
    UnknownStatus(String),

    /// The execution requests list breaks EIP-7685 ordering or encoding.
    #[error("{0}")]
    Requests(RequestsError),

    /// Lists that must agree in length do not.
    ///
    /// Blob bundles need one commitment per blob and a fixed number of cell proofs per blob.
    #[error("length {actual} disagrees with the expected {expected}")]
    LengthMismatch {
        /// The length the other lists imply.
        expected: usize,
        /// The length found.
        actual: usize,
    },
}

/// An execution requests list that breaks EIP-7685 or the consensus encoding.
///
/// See `get_execution_requests` in the Electra validator spec.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RequestsError {
    /// An element is empty, without even a type byte.
    #[error("request element has no type byte")]
    MissingType,

    /// A type byte names no known request type.
    #[error("unknown request type 0x{0:02x}")]
    UnknownType(u8),

    /// An element is only a type byte, with no request data after it.
    #[error("request type 0x{0:02x} has no data")]
    Empty(u8),

    /// A type does not strictly exceed the one before it, so the list is unordered or repeats.
    #[error("request type 0x{current:02x} follows 0x{previous:02x}, not strictly ascending")]
    OutOfOrder {
        /// The type before.
        previous: u8,
        /// The type that should have been larger.
        current: u8,
    },

    /// The request data is not the SSZ list its type requires.
    #[error("request type 0x{0:02x}: {1}")]
    Ssz(u8, DecodeError),
}
