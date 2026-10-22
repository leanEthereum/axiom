//! What a connection reports to its owner.

use super::{ConnectionError, StreamId};
use crate::tls::VerifiedPeer;

/// Something the peer did, or a change of the connection's state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The handshake completed and the peer proved its identity.
    Connected(VerifiedPeer),
    /// The peer opened a stream.
    InboundStream(StreamId),
    /// Data arrived on a stream, in order.
    Data {
        /// The stream.
        stream: StreamId,
        /// The bytes.
        data: Vec<u8>,
    },
    /// The peer finished its side of a stream: no more data will arrive on it.
    StreamFinished(StreamId),
    /// The peer aborted a stream.
    StreamReset(StreamId),
    /// The connection ended; no further event follows.
    Closed(ConnectionError),
}
