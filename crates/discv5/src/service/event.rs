//! What the service hands back to its driver.

use std::net::{SocketAddr, SocketAddrV4};

use super::{Datagram, LookupId};
use crate::{enr::Enr, message::RequestId, node_id::NodeId};

/// A happening the application may act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A node joined the routing table.
    Discovered(Box<Enr>),

    /// A peer answered an application PING.
    Pong {
        /// The peer.
        node: NodeId,
        /// The request answered.
        request_id: RequestId,
        /// The peer's record sequence number.
        enr_seq: u64,
        /// The local endpoint as the peer sees it.
        observed: SocketAddr,
    },

    /// Enough peers agreed on a new external endpoint for this node.
    ///
    /// Every PONG counts, those answering liveness checks included.
    ExternalAddress {
        /// The IPv4 endpoint peers see.
        address: SocketAddrV4,
        /// Distinct voter networks that agreed.
        votes: usize,
    },

    /// A peer answered an application FINDNODE.
    NodesFound {
        /// The peer.
        node: NodeId,
        /// The request answered.
        request_id: RequestId,
        /// The records at the requested distances.
        enrs: Vec<Enr>,
    },

    /// A peer sent a TALKREQ; the application answers it through the service.
    TalkRequest {
        /// The peer.
        node: NodeId,
        /// The peer's endpoint.
        addr: SocketAddr,
        /// The id to answer under.
        request_id: RequestId,
        /// The application protocol.
        protocol: Vec<u8>,
        /// The payload.
        request: Vec<u8>,
    },

    /// A peer answered an application TALKREQ.
    TalkResponse {
        /// The peer.
        node: NodeId,
        /// The request answered.
        request_id: RequestId,
        /// The payload.
        response: Vec<u8>,
    },

    /// An application request went unanswered.
    RequestFailed {
        /// The peer.
        node: NodeId,
        /// The request.
        request_id: RequestId,
    },

    /// A lookup ended.
    LookupFinished {
        /// The lookup.
        id: LookupId,
        /// The id searched for.
        target: NodeId,
        /// Matching records, nearest to the target first.
        peers: Vec<Enr>,
    },
}

/// One output of the service: a datagram to send or an event to report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Send a datagram.
    Send(Datagram),

    /// Report an event.
    Event(Event),
}
