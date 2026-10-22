//! What a sent packet carried, so an acknowledgment or a loss can be applied to its frames.

use std::time::Duration;

use crate::quic::{
    packet::PacketNumber,
    stream::{Chunk, StreamRecord},
};

/// A frame worth remembering until its packet is acknowledged or lost.
///
/// PADDING, ACK and PATH_RESPONSE frames are not repeated, so they leave no record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SentFrame {
    /// A stream-related frame.
    Stream(StreamRecord),
    /// Handshake bytes in the packet's level.
    Crypto(Chunk),
    /// A HANDSHAKE_DONE.
    HandshakeDone,
    /// A PING; nothing to repeat.
    Ping,
    /// A RETIRE_CONNECTION_ID.
    RetireConnectionId {
        /// The sequence number retired.
        sequence: u64,
    },
}

/// One sent packet, until acknowledged or declared lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SentPacket {
    /// The packet number.
    pub(crate) number: PacketNumber,
    /// When it was sent.
    pub(crate) time_sent: Duration,
    /// Bytes on the wire.
    pub(crate) size: u64,
    /// Whether it obliges the peer to acknowledge.
    pub(crate) ack_eliciting: bool,
    /// Whether it counts against the congestion window: everything but ACK-only packets.
    pub(crate) in_flight: bool,
    /// The frames to act on later.
    pub(crate) frames: Vec<SentFrame>,
}
