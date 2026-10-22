//! What the packet layer reports to the protocol layer.

use std::net::SocketAddr;

use crate::{enr::Enr, message::Message, node_id::NodeId};

/// An authenticated happening on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HandlerEvent {
    /// A peer proved its identity in a handshake it initiated.
    Established {
        /// The peer's record.
        enr: Enr,
        /// The endpoint the handshake came from.
        addr: SocketAddr,
    },

    /// A peer sent a request.
    Request {
        /// The sender.
        node: NodeId,
        /// The endpoint it came from.
        addr: SocketAddr,
        /// The request.
        message: Message,
    },

    /// A peer answered one of this node's requests.
    Response {
        /// The responder.
        node: NodeId,
        /// The request.
        request: Message,
        /// The response.
        message: Message,
    },
}
