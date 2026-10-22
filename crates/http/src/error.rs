//! Errors of the wire format and of the transport.

use std::{io, time::Duration};

use thiserror::Error;

use crate::StatusCode;

/// A message that breaks HTTP/1.1 framing or a configured limit.
///
/// These come from the pure parsers, so they compare equal in tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The head, or a chunked body's trailer section, is longer than the limit allows.
    ///
    /// The parser stops at the limit, so the full length is never known.
    #[error("message head exceeds the limit of {limit} bytes")]
    HeadTooLarge {
        /// The most bytes allowed.
        limit: usize,
    },

    /// The head has more fields than the limit allows.
    #[error("message head has more than {limit} fields")]
    TooManyHeaders {
        /// The most fields allowed.
        limit: usize,
    },

    /// The body is longer than the limit allows.
    ///
    /// The size is exact for a declared length and a lower bound otherwise.
    /// The reader refuses a body as soon as it crosses the limit, before reading the rest.
    #[error("message body of at least {size} bytes exceeds the limit of {limit} bytes")]
    BodyTooLarge {
        /// The body bytes declared or received so far.
        size: u64,
        /// The most bytes allowed.
        limit: usize,
    },

    /// The request line is not a method, a target, and a version.
    #[error("malformed request line")]
    InvalidRequestLine,

    /// The method is not one this implementation serves.
    #[error("unsupported request method")]
    UnknownMethod,

    /// The target is not in origin form, a path starting with a slash.
    #[error("request target is not an absolute path")]
    InvalidTarget,

    /// The status line is not a version, a code, and a reason.
    #[error("malformed status line")]
    InvalidStatusLine,

    /// The version is neither HTTP/1.1 nor HTTP/1.0.
    #[error("unsupported protocol version")]
    UnsupportedVersion,

    /// A field line is not a token, a colon, and a value.
    #[error("malformed header field at position {index}")]
    InvalidHeader {
        /// The zero-based position of the field line in the head.
        index: usize,
    },

    /// A content length is not a decimal number.
    #[error("malformed content length")]
    InvalidContentLength,

    /// Two content lengths disagree.
    ///
    /// RFC 9112 section 6.3 makes this a request smuggling hazard.
    #[error("content lengths {first} and {second} disagree")]
    ConflictingLength {
        /// The first length declared.
        first: u64,
        /// The later length that differs.
        second: u64,
    },

    /// A message declares both a transfer coding and a content length.
    ///
    /// RFC 9112 section 6.3 makes this a request smuggling hazard.
    #[error("message declares both a transfer coding and content length {content_length}")]
    CodingWithLength {
        /// The declared content length.
        content_length: u64,
    },

    /// A transfer coding other than chunked alone.
    #[error("unsupported transfer coding")]
    UnsupportedTransferEncoding,

    /// A chunk size line or chunk delimiter is malformed.
    #[error("malformed chunked body")]
    InvalidChunk,

    /// The connection ended inside a message.
    #[error("connection closed inside a message")]
    UnexpectedEof,
}

impl ProtocolError {
    /// The status a server answers with when a request breaks this rule.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::HeadTooLarge { .. } | Self::TooManyHeaders { .. } => {
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
            }
            Self::BodyTooLarge { .. } => StatusCode::CONTENT_TOO_LARGE,
            Self::UnknownMethod | Self::UnsupportedTransferEncoding => StatusCode::NOT_IMPLEMENTED,
            Self::UnsupportedVersion => StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

/// A failure to exchange a message.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HttpError {
    /// The peer broke the protocol.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// The socket failed.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// The exchange, or the connect inside it, did not finish in time.
    #[error("timed out after {after:?}")]
    Timeout {
        /// The timeout that expired.
        after: Duration,
    },

    /// The peer closed the connection before sending a response.
    #[error("connection closed before a response")]
    Closed,

    /// The URL is not an http URL with a host.
    #[error("not an http URL with a host")]
    InvalidUrl,

    /// A cross-origin policy names neither the wildcard nor an origin.
    #[error("{origin:?} is neither * nor an origin such as http://localhost:5062")]
    InvalidOrigin {
        /// The text given.
        origin: String,
    },

    /// A field name or value cannot be written without corrupting the message.
    ///
    /// The value stays out of the error, as it may carry a credential.
    #[error("header field {name:?} cannot be written")]
    InvalidHeader {
        /// The field name, quoted with escapes when printed.
        name: String,
    },
}

impl HttpError {
    /// Whether the failure shows a pooled connection was already dead before the request.
    ///
    /// The server may close an idle keep-alive connection at any moment.
    /// A request that meets such a socket never reached a handler, so a fresh connection may retry it.
    pub(crate) fn is_stale_connection(&self) -> bool {
        match self {
            Self::Closed => true,
            Self::Io(error) => matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            ),
            _ => false,
        }
    }
}
