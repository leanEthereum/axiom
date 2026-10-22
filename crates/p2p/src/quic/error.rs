//! Why a packet, a stream call, or a whole connection fails.

use std::fmt;

use thiserror::Error;

use super::StreamId;
use crate::tls::TlsError;

/// Received bytes that do not parse.
///
/// The peer controls every byte, so each variant names what broke and where.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input ends before a field it announces.
    #[error("input truncated: {needed} bytes needed, {available} available")]
    Truncated {
        /// Bytes the field needs.
        needed: usize,
        /// Bytes left in the input.
        available: usize,
    },

    /// A frame type no version 1 endpoint knows.
    #[error("unknown frame type {frame_type:#x}")]
    UnknownFrame {
        /// The type read.
        frame_type: u64,
    },

    /// A frame whose fields break a rule of its definition.
    #[error("malformed frame of type {frame_type:#x}: {rule}")]
    MalformedFrame {
        /// The frame type.
        frame_type: u64,
        /// The rule broken, as RFC 9000 states it.
        rule: &'static str,
    },

    /// A connection id longer than 20 bytes.
    #[error("connection id of {len} bytes exceeds the 20-byte limit")]
    ConnectionIdTooLong {
        /// The length announced.
        len: usize,
    },

    /// A packet header that breaks a rule of RFC 9000, section 17.
    #[error("malformed packet header: {rule}")]
    MalformedHeader {
        /// The rule broken.
        rule: &'static str,
    },

    /// A transport parameter that breaks a rule of RFC 9000, section 18.
    #[error("invalid transport parameter {id:#x}: {rule}")]
    TransportParameter {
        /// The parameter identifier.
        id: u64,
        /// The rule broken.
        rule: &'static str,
    },
}

/// A transport error code, per RFC 9000, section 20.1.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransportErrorCode(pub u64);

impl TransportErrorCode {
    /// The connection closes without error.
    pub const NO_ERROR: Self = Self(0x00);
    /// The endpoint hit an internal error.
    pub const INTERNAL_ERROR: Self = Self(0x01);
    /// The server refuses to accept a new connection.
    pub const CONNECTION_REFUSED: Self = Self(0x02);
    /// More data arrived than the advertised limits allow.
    pub const FLOW_CONTROL_ERROR: Self = Self(0x03);
    /// A stream id exceeded the advertised stream limit.
    pub const STREAM_LIMIT_ERROR: Self = Self(0x04);
    /// A frame arrived for a stream in a state that forbids it.
    pub const STREAM_STATE_ERROR: Self = Self(0x05);
    /// A stream's final size changed or was exceeded.
    pub const FINAL_SIZE_ERROR: Self = Self(0x06);
    /// A frame was badly formatted.
    pub const FRAME_ENCODING_ERROR: Self = Self(0x07);
    /// Transport parameters were malformed or invalid.
    pub const TRANSPORT_PARAMETER_ERROR: Self = Self(0x08);
    /// The peer issued more connection ids than allowed.
    pub const CONNECTION_ID_LIMIT_ERROR: Self = Self(0x09);
    /// A protocol rule was broken that has no more specific code.
    pub const PROTOCOL_VIOLATION: Self = Self(0x0a);
    /// An invalid Retry token arrived.
    pub const INVALID_TOKEN: Self = Self(0x0b);
    /// The application closed the connection.
    pub const APPLICATION_ERROR: Self = Self(0x0c);
    /// More CRYPTO data arrived than can be buffered.
    pub const CRYPTO_BUFFER_EXCEEDED: Self = Self(0x0d);
    /// A key update broke a rule.
    pub const KEY_UPDATE_ERROR: Self = Self(0x0e);
    /// A key reached its AEAD usage limit.
    pub const AEAD_LIMIT_REACHED: Self = Self(0x0f);

    /// The code of a TLS alert, per RFC 9001, section 4.8.
    #[must_use]
    pub const fn crypto(alert: u8) -> Self {
        Self(0x100 | alert as u64)
    }
}

impl fmt::Debug for TransportErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for TransportErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// A connection error this endpoint detected, sent to the peer in a close frame.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("transport error {code} on frame type {frame_type:?}: {reason}")]
pub struct TransportError {
    /// The code sent.
    pub code: TransportErrorCode,
    /// The type of the frame that triggered it, when one did.
    pub frame_type: Option<u64>,
    /// A reason phrase for the log and the peer.
    pub reason: String,
}

impl TransportError {
    /// An error with a code and a reason, tied to no frame.
    #[must_use]
    pub fn new(code: TransportErrorCode, reason: impl Into<String>) -> Self {
        Self {
            code,
            frame_type: None,
            reason: reason.into(),
        }
    }

    /// The same error, tied to the frame that triggered it.
    #[must_use]
    pub const fn on_frame(mut self, frame_type: u64) -> Self {
        self.frame_type = Some(frame_type);
        self
    }

    /// A protocol violation with a reason.
    #[must_use]
    pub fn protocol(reason: impl Into<String>) -> Self {
        Self::new(TransportErrorCode::PROTOCOL_VIOLATION, reason)
    }
}

impl From<DecodeError> for TransportError {
    fn from(error: DecodeError) -> Self {
        let code = match error {
            DecodeError::TransportParameter { .. } => TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            DecodeError::ConnectionIdTooLong { .. } => TransportErrorCode::PROTOCOL_VIOLATION,
            _ => TransportErrorCode::FRAME_ENCODING_ERROR,
        };
        Self::new(code, error.to_string())
    }
}

impl From<TlsError> for TransportError {
    fn from(error: TlsError) -> Self {
        Self::new(TransportErrorCode::crypto(error.alert()), error.to_string())
    }
}

/// Why a connection ended.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConnectionError {
    /// This endpoint found an error and closed the connection.
    #[error("closed locally: {0}")]
    Transport(#[from] TransportError),

    /// The peer closed with a transport error.
    #[error("peer closed with transport error {code}: {reason}")]
    PeerTransport {
        /// The code the peer sent.
        code: TransportErrorCode,
        /// The peer's reason phrase, lossily decoded.
        reason: String,
    },

    /// The peer's application closed the connection.
    #[error("peer application closed with code {code}: {reason}")]
    PeerApplication {
        /// The application code.
        code: u64,
        /// The peer's reason phrase, lossily decoded.
        reason: String,
    },

    /// This side's owner closed the connection.
    #[error("closed by this side with code {code}")]
    LocallyClosed {
        /// The application code sent.
        code: u64,
    },

    /// No packet arrived within the idle timeout.
    #[error("idle timeout")]
    TimedOut,

    /// The server speaks none of the versions this client offers.
    #[error("no common QUIC version; the server offers {offered:?}")]
    VersionMismatch {
        /// The versions in the server's Version Negotiation packet.
        offered: Vec<u32>,
    },
}

/// A misuse of the stream API, or a call the connection's state forbids.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QuicError {
    /// The handshake has not completed, so no stream may open yet.
    #[error("connection not established")]
    NotEstablished,

    /// The connection is closing or closed.
    #[error("connection closed")]
    Closed,

    /// The peer's stream limit allows no further stream.
    #[error("peer allows {max} bidirectional streams, all opened")]
    StreamLimit {
        /// The peer's limit.
        max: u64,
    },

    /// No such stream is open.
    #[error("unknown stream {0}")]
    UnknownStream(StreamId),

    /// The stream's sending side is finished or reset.
    #[error("stream {0} is closed for writing")]
    StreamClosed(StreamId),

    /// The stream's send buffer cannot take the write.
    #[error("stream {stream}: write of {len} bytes over {pending} pending exceeds {max}")]
    SendBufferFull {
        /// The stream.
        stream: StreamId,
        /// Bytes offered.
        len: usize,
        /// Bytes already waiting.
        pending: usize,
        /// The buffer cap.
        max: usize,
    },
}
