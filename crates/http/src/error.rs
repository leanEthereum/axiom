//! Errors of the wire format and of the transport.

use std::{error::Error, fmt, io};

use crate::StatusCode;

/// A message that breaks HTTP/1.1 framing or a configured limit.
///
/// These come from the pure parsers, so they compare equal in tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The head is longer than the limit allows.
    HeadTooLarge,

    /// The head has more fields than the limit allows.
    TooManyHeaders,

    /// The body is longer than the limit allows.
    BodyTooLarge,

    /// The request line is not a method, a target, and a version.
    InvalidRequestLine,

    /// The method is not one this implementation serves.
    UnknownMethod,

    /// The target is not in origin form, a path starting with a slash.
    InvalidTarget,

    /// The status line is not a version, a code, and a reason.
    InvalidStatusLine,

    /// The version is neither HTTP/1.1 nor HTTP/1.0.
    UnsupportedVersion,

    /// A field line is not a token, a colon, and a value.
    InvalidHeader,

    /// A content length is not a decimal number.
    InvalidContentLength,

    /// The message declares its length twice in ways that disagree.
    ///
    /// RFC 9112 section 6.3 makes this a request smuggling hazard.
    ConflictingLength,

    /// A transfer coding other than chunked alone.
    UnsupportedTransferEncoding,

    /// A chunk size line or chunk delimiter is malformed.
    InvalidChunk,

    /// The connection ended inside a message.
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

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HeadTooLarge => "message head exceeds the size limit",
            Self::TooManyHeaders => "message head has too many fields",
            Self::BodyTooLarge => "message body exceeds the size limit",
            Self::InvalidRequestLine => "malformed request line",
            Self::UnknownMethod => "unsupported request method",
            Self::InvalidTarget => "request target is not an absolute path",
            Self::InvalidStatusLine => "malformed status line",
            Self::UnsupportedVersion => "unsupported protocol version",
            Self::InvalidHeader => "malformed header field",
            Self::InvalidContentLength => "malformed content length",
            Self::ConflictingLength => "message length is declared inconsistently",
            Self::UnsupportedTransferEncoding => "unsupported transfer coding",
            Self::InvalidChunk => "malformed chunked body",
            Self::UnexpectedEof => "connection closed inside a message",
        })
    }
}

impl Error for ProtocolError {}

/// A failure to exchange a message.
#[derive(Debug)]
#[non_exhaustive]
pub enum HttpError {
    /// The peer broke the protocol.
    Protocol(ProtocolError),

    /// The socket failed.
    Io(io::Error),

    /// The exchange did not finish in time.
    Timeout,

    /// The peer closed the connection before sending a response.
    Closed,

    /// The URL is not an http URL with a host.
    InvalidUrl,

    /// A field name or value cannot be written without corrupting the message.
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

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "protocol error: {error}"),
            Self::Io(error) => write!(f, "i/o error: {error}"),
            Self::Timeout => f.write_str("timed out"),
            Self::Closed => f.write_str("connection closed before a response"),
            Self::InvalidUrl => f.write_str("not an http URL with a host"),
            Self::InvalidHeader => f.write_str("header field cannot be written"),
        }
    }
}

impl Error for HttpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ProtocolError> for HttpError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<io::Error> for HttpError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
