//! Errors of the engine API client.

use std::{
    error::Error,
    fmt::{self, Write},
};

use axiom_http::{HttpError, StatusCode};
use axiom_json::{HexError, ParseError};
use axiom_ssz::DecodeError;

use crate::RpcError;

/// A call to the execution engine that did not produce a typed result.
#[derive(Debug)]
#[non_exhaustive]
pub enum EngineError {
    /// The HTTP exchange failed: connection, timeout, or framing.
    Http(HttpError),

    /// The engine answered with a status other than 200.
    ///
    /// A 401 or 403 means it rejected the token: check the shared secret and the clocks.
    Status(StatusCode),

    /// The response body is not JSON.
    Json(ParseError),

    /// The response is JSON but not a JSON-RPC 2.0 response to this request.
    Envelope(EnvelopeError),

    /// The engine returned a JSON-RPC error object.
    Rpc(RpcError),

    /// The result does not map onto the expected structure.
    Wire(WireError),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(error) => write!(f, "engine transport: {error}"),
            Self::Status(status) => write!(f, "engine replied with HTTP status {status}"),
            Self::Json(error) => write!(f, "engine response is not JSON: {error}"),
            Self::Envelope(error) => write!(f, "engine response is not JSON-RPC: {error}"),
            Self::Rpc(error) => write!(f, "engine error: {error}"),
            Self::Wire(error) => write!(f, "engine result is malformed: {error}"),
        }
    }
}

impl Error for EngineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Http(error) => Some(error),
            Self::Status(_) => None,
            Self::Json(error) => Some(error),
            Self::Envelope(error) => Some(error),
            Self::Rpc(error) => Some(error),
            Self::Wire(error) => Some(error),
        }
    }
}

impl From<HttpError> for EngineError {
    fn from(error: HttpError) -> Self {
        Self::Http(error)
    }
}

impl From<RpcError> for EngineError {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}

impl From<WireError> for EngineError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<EnvelopeError> for EngineError {
    fn from(error: EnvelopeError) -> Self {
        Self::Envelope(error)
    }
}

/// A response that breaks the JSON-RPC 2.0 envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The response is not an object.
    NotAnObject,

    /// The version member is missing or not "2.0".
    WrongVersion,

    /// The id does not echo the request's id.
    IdMismatch,

    /// Neither or both of the result and error members are present.
    ResultOrError,

    /// The error member lacks an integer code or a string message.
    MalformedError,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAnObject => "response is not an object",
            Self::WrongVersion => "jsonrpc member is not \"2.0\"",
            Self::IdMismatch => "id does not match the request",
            Self::ResultOrError => "response needs exactly one of result and error",
            Self::MalformedError => "error object lacks a code or message",
        })
    }
}

impl Error for EnvelopeError {}

/// A JSON value that does not map onto an engine API structure.
///
/// The path locates the value, as in `executionPayload.withdrawals[2].amount`.
#[derive(Clone, Debug, PartialEq, Eq)]
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
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}", self.kind)
        } else {
            write!(f, "{}: {}", self.path(), self.kind)
        }
    }
}

impl Error for WireError {}

impl From<WireErrorKind> for WireError {
    fn from(kind: WireErrorKind) -> Self {
        Self::new(kind)
    }
}

/// The rule a JSON value broke.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireErrorKind {
    /// A required member is absent or null.
    Missing,

    /// The value has the wrong JSON type.
    Type {
        /// The JSON type the structure requires.
        expected: &'static str,
        /// The JSON type found.
        found: &'static str,
    },

    /// A QUANTITY or DATA string is malformed.
    Hex(HexError),

    /// A list holds more items or bytes than its type allows.
    TooLong {
        /// The most the type allows.
        limit: usize,
        /// The count found.
        actual: usize,
    },

    /// A fixed-size value has the wrong length.
    WrongLength {
        /// The length the type requires.
        expected: usize,
        /// The length found.
        actual: usize,
    },

    /// A payload status string outside the five the spec defines.
    UnknownStatus(String),

    /// The execution requests list breaks EIP-7685 ordering or encoding.
    Requests(RequestsError),

    /// Lists that must agree in length do not.
    ///
    /// Blob bundles need one commitment per blob and a fixed number of cell proofs per blob.
    LengthMismatch {
        /// The length the other lists imply.
        expected: usize,
        /// The length found.
        actual: usize,
    },
}

impl fmt::Display for WireErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("required value is missing"),
            Self::Type { expected, found } => write!(f, "expected {expected}, found {found}"),
            Self::Hex(error) => write!(f, "{error}"),
            Self::TooLong { limit, actual } => write!(f, "{actual} items exceed the limit {limit}"),
            Self::WrongLength { expected, actual } => {
                write!(f, "length {actual}, expected {expected}")
            }
            Self::UnknownStatus(status) => write!(f, "unknown payload status {status:?}"),
            Self::Requests(error) => write!(f, "{error}"),
            Self::LengthMismatch { expected, actual } => {
                write!(f, "length {actual} disagrees with the expected {expected}")
            }
        }
    }
}

/// An execution requests list that breaks EIP-7685 or the consensus encoding.
///
/// See `get_execution_requests` in the Electra validator spec.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestsError {
    /// An element is empty, without even a type byte.
    MissingType,

    /// A type byte names no known request type.
    UnknownType(u8),

    /// An element is only a type byte, with no request data after it.
    Empty(u8),

    /// A type does not strictly exceed the one before it, so the list is unordered or repeats.
    OutOfOrder {
        /// The type before.
        previous: u8,
        /// The type that should have been larger.
        current: u8,
    },

    /// The request data is not the SSZ list its type requires.
    Ssz(u8, DecodeError),
}

impl fmt::Display for RequestsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingType => f.write_str("request element has no type byte"),
            Self::UnknownType(kind) => write!(f, "unknown request type 0x{kind:02x}"),
            Self::Empty(kind) => write!(f, "request type 0x{kind:02x} has no data"),
            Self::OutOfOrder { previous, current } => write!(
                f,
                "request type 0x{current:02x} follows 0x{previous:02x}, not strictly ascending"
            ),
            Self::Ssz(kind, error) => write!(f, "request type 0x{kind:02x}: {error}"),
        }
    }
}

impl Error for RequestsError {}
