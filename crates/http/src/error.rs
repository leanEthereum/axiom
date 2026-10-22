//! Errors of the wire format and of the transport.

use std::io;

use thiserror::Error;

use crate::StatusCode;

/// A message that breaks HTTP/1.1 framing or a configured limit.
///
/// These come from the pure parsers, so they compare equal in tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The head is longer than the limit allows.
    #[error("message head exceeds the size limit")]
    HeadTooLarge,

    /// The head has more fields than the limit allows.
    #[error("message head has too many fields")]
    TooManyHeaders,

    /// The body is longer than the limit allows.
    #[error("message body exceeds the size limit")]
    BodyTooLarge,

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
    #[error("malformed header field")]
    InvalidHeader,

    /// A content length is not a decimal number.
    #[error("malformed content length")]
    InvalidContentLength,

    /// The message declares its length twice in ways that disagree.
    ///
    /// RFC 9112 section 6.3 makes this a request smuggling hazard.
    #[error("message length is declared inconsistently")]
    ConflictingLength,

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
            Self::HeadTooLarge | Self::TooManyHeaders => {
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
            }
            Self::BodyTooLarge => StatusCode::CONTENT_TOO_LARGE,
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

    /// The exchange did not finish in time.
    #[error("timed out")]
    Timeout,

    /// The peer closed the connection before sending a response.
    #[error("connection closed before a response")]
    Closed,

    /// The URL is not an http URL with a host.
    #[error("not an http URL with a host")]
    InvalidUrl,

    /// A field name or value cannot be written without corrupting the message.
    #[error("header field cannot be written")]
    InvalidHeader,
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
