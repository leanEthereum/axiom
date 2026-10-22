//! Yamux: many logical streams over one ordered byte stream.
//!
//! # Overview
//!
//! Every frame opens with a 12-byte header naming its stream.
//! Streams open with a SYN flag, close with FIN, and abort with RST.
//!
//! ```text
//! client (odd ids)                                server (even ids)
//!   ── window update, SYN, stream 1 ───────────────▶
//!   ── data, stream 1, "hello" ────────────────────▶   no need to wait for the ACK
//!   ◀────────────────── window update, ACK, stream 1 ──
//!   ◀──────────────────── data, FIN, stream 1, "hi" ──   half-close from the server
//!   ── data, FIN, stream 1 ────────────────────────▶   fully closed
//! ```
//!
//! Each stream starts with a 256 KiB receive window per direction.
//! A sender may only have that many unacknowledged data bytes in flight.
//! The receiver grants more with window update frames as its application consumes data.
//! A peer that outpaces the application therefore stalls at the window, not in memory.
//!
//! The protocol identifier is `/yamux/1.0.0`.
//! See `libp2p/specs/yamux/README.md`, a copy of the hashicorp specification.

mod frame;
mod session;

pub use frame::{Flags, FrameType, HEADER_LEN, Header, StreamId};
pub use session::{Mode, Session, SessionEvent};
use thiserror::Error;

/// The multistream-select name of the protocol.
pub const PROTOCOL: &str = "/yamux/1.0.0";

/// The window both sides assume for every new stream, fixed by the specification.
pub const INITIAL_WINDOW: u32 = 256 * 1024;

/// Tunables of a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Receive window granted to each stream.
    ///
    /// Values above the initial window are announced in the SYN or ACK frame.
    pub receive_window: u32,

    /// Most streams open at once; extra inbound streams are reset.
    pub max_streams: usize,

    /// Most outbound streams the peer has not yet acknowledged.
    ///
    /// The specification recommends 256, as the only backpressure on stream creation.
    pub max_ack_backlog: usize,

    /// Largest data frame payload written.
    ///
    /// Smaller frames interleave streams more fairly on one connection.
    pub max_frame_len: u32,

    /// Most bytes one stream holds back while the peer withholds credit.
    ///
    /// A write to an idle stream is always accepted, so one message may exceed it.
    /// Beyond it, writes fail until the peer grants credit and the queue drains.
    pub max_send_buffer: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            receive_window: INITIAL_WINDOW,
            max_streams: 512,
            max_ack_backlog: 256,
            max_frame_len: 16 * 1024,
            // Four default windows: a peer that stops reading costs at most this per stream.
            max_send_buffer: 4 * INITIAL_WINDOW as usize,
        }
    }
}

/// Reason codes of a go-away frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GoAwayCode {
    /// Orderly shutdown.
    Normal,
    /// The peer broke the protocol.
    ProtocolError,
    /// The sender failed internally.
    InternalError,
    /// A code outside the specification.
    Unknown(u32),
}

impl GoAwayCode {
    /// The value carried in the length field.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::Normal => 0,
            Self::ProtocolError => 1,
            Self::InternalError => 2,
            Self::Unknown(code) => code,
        }
    }

    /// The reason a length field names.
    #[must_use]
    pub const fn from_code(code: u32) -> Self {
        match code {
            0 => Self::Normal,
            1 => Self::ProtocolError,
            2 => Self::InternalError,
            other => Self::Unknown(other),
        }
    }
}

/// A violation by the peer, or a request this session cannot honour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum YamuxError {
    /// A header names a version other than zero.
    #[error("unsupported yamux version {0}")]
    InvalidVersion(u8),

    /// A header names a frame type outside the four defined.
    #[error("unknown frame type {0}")]
    InvalidFrameType(u8),

    /// A frame uses a stream identifier the peer may not use.
    ///
    /// The cause is either zero on a stream frame or the opener's parity on a SYN.
    #[error("invalid stream identifier {0}")]
    InvalidStreamId(StreamId),

    /// A SYN reuses a stream identifier that is still open.
    #[error("stream {0} is already open")]
    DuplicateStream(StreamId),

    /// A data frame exceeds the receive window left on its stream.
    #[error("{len} bytes on stream {stream} exceed its window of {window}")]
    WindowExceeded {
        /// The stream.
        stream: StreamId,
        /// Payload length of the frame.
        len: u32,
        /// Window left before the frame.
        window: u32,
    },

    /// A window update pushes the send window past 2^32 - 1.
    #[error("window of stream {0} overflows")]
    WindowOverflow(StreamId),

    /// The stream is not open on this session.
    #[error("stream {0} is not open")]
    UnknownStream(StreamId),

    /// The stream was already half-closed by this side.
    #[error("stream {0} is closed for writing")]
    StreamClosed(StreamId),

    /// A go-away was sent or received, so no new stream may open.
    #[error("session is going away")]
    SessionClosing,

    /// Too many outbound streams await the peer's acknowledgement.
    #[error("too many unacknowledged streams")]
    AckBacklogFull,

    /// Stream identifiers of this side are exhausted.
    #[error("stream identifiers exhausted")]
    StreamIdsExhausted,

    /// The stream already holds back as many bytes as the send buffer allows.
    #[error("send buffer of stream {0} is full")]
    SendBufferFull(StreamId),
}
