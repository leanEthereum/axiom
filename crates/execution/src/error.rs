//! Errors of the engine API client.

use std::fmt::Write;

use axiom_http::{HttpError, StatusCode};
use axiom_json::{HexError, Json, ParseError};
use axiom_ssz::DecodeError;
use axiom_types::{ForkName, Hash32};
use thiserror::Error;

use crate::{ForkchoiceVersion, RpcError};

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

    /// The fork calls no method of the family, as before the merge or before blobs.
    #[error("the {fork} fork calls no {family} method")]
    NoMethod {
        /// The fork asked for.
        fork: ForkName,
        /// The method family, such as engine_getBlobs.
        family: &'static str,
    },

    /// The engine answered a list request with another number of entries than allowed.
    #[error("engine answered {method} with {actual} entries, where {expected} were asked")]
    Length {
        /// The method.
        method: &'static str,
        /// Entries asked for, the most the reply may hold.
        expected: usize,
        /// Entries in the reply.
        actual: usize,
    },

    /// The engine answered a block lookup with another block.
    #[error("asked for block {requested}, the engine returned block {returned}")]
    BlockMismatch {
        /// The hash looked up.
        requested: Hash32,
        /// The hash of the block returned.
        returned: Hash32,
    },

    /// The build attributes are of another version than the fork's fork choice method.
    #[error("the {fork} fork calls {expected}, but the attributes are for {actual}")]
    AttributesVersion {
        /// The fork asked for.
        fork: ForkName,
        /// The method the fork calls.
        expected: ForkchoiceVersion,
        /// The method the attributes belong to.
        actual: ForkchoiceVersion,
    },
}

/// A payload that cannot become a request for the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum NewPayloadError {
    /// The bid commits to more blobs than a block can hold.
    #[error("bid commits to {count} blobs, above the limit {limit}")]
    TooManyBlobs {
        /// The number of commitments in the bid.
        count: usize,
        /// The most commitments a block can hold.
        limit: usize,
    },
}

/// A response that breaks the JSON-RPC 2.0 envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The response is not an object.
    #[error("response is a JSON {found}, not an object")]
    NotAnObject {
        /// The JSON type of the response.
        found: &'static str,
    },

    /// The version member is missing or not "2.0".
    #[error("jsonrpc member is not \"2.0\"")]
    WrongVersion,

    /// The id is absent, or not an integer as this client's ids always are.
    #[error("response lacks the integer id {expected} of its request")]
    MissingId {
        /// The id the request carried.
        expected: u64,
    },

    /// The id does not echo the request's id.
    #[error("response id {found} does not echo request id {expected}")]
    IdMismatch {
        /// The id the request carried.
        expected: u64,
        /// The id the response carried.
        found: u64,
    },

    /// Neither or both of the result and error members are present.
    #[error("response holds {present} of the result and error members, not exactly one")]
    ResultOrError {
        /// How many of the two members are present: zero or two.
        present: usize,
    },

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

    /// The error for a value of the wrong JSON type.
    pub(crate) const fn wrong_type(expected: &'static str, found: &Json) -> Self {
        Self::new(WireErrorKind::Type {
            expected,
            found: found.kind(),
        })
    }

    /// The error for a malformed QUANTITY or DATA string.
    pub(crate) const fn hex(error: HexError) -> Self {
        match error {
            // A DATA of the wrong size is a length problem, not an encoding one.
            HexError::WrongLength { expected, actual } => {
                Self::new(WireErrorKind::WrongLength { expected, actual })
            }
            other => Self::new(WireErrorKind::Hex(other)),
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
    #[error("request element {index} has no type byte")]
    MissingType {
        /// The element's position in the list.
        index: usize,
    },

    /// A type byte names no known request type.
    #[error("request element {index} has unknown type 0x{kind:02x}")]
    UnknownType {
        /// The element's position in the list.
        index: usize,
        /// The type byte found.
        kind: u8,
    },

    /// An element is only a type byte, with no request data after it.
    #[error("request element {index} of type 0x{kind:02x} has no data")]
    Empty {
        /// The element's position in the list.
        index: usize,
        /// The element's type byte.
        kind: u8,
    },

    /// A type does not strictly exceed the one before it, so the list is unordered or repeats.
    #[error("request type 0x{current:02x} follows 0x{previous:02x}, not strictly ascending")]
    OutOfOrder {
        /// The type before.
        previous: u8,
        /// The type that should have been larger.
        current: u8,
    },

    /// The request data is not the SSZ list its type requires.
    ///
    /// Types strictly ascend, so the type alone locates the element.
    #[error("request type 0x{0:02x}: {1}")]
    Ssz(u8, DecodeError),
}
