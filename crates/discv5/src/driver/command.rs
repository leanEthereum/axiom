//! What the handle asks of the driver task.

use std::net::SocketAddr;

use tokio::sync::oneshot;

use crate::{
    distance::LogDistance,
    enr::Enr,
    message::RequestId,
    node_id::NodeId,
    service::{EnrFilter, LookupId, ServiceError},
    table::InsertOutcome,
};

/// A request from the handle, with a channel for the immediate reply where one exists.
#[derive(Debug)]
pub(crate) enum Command {
    /// Add a known record.
    AddEnr(Enr, oneshot::Sender<InsertOutcome>),
    /// Ping a node.
    Ping(Enr, oneshot::Sender<Option<RequestId>>),
    /// Ask a node for records at distances.
    FindNode(Enr, Vec<LogDistance>, oneshot::Sender<Option<RequestId>>),
    /// Send an application request.
    TalkRequest {
        /// The peer.
        enr: Enr,
        /// The application protocol.
        protocol: Vec<u8>,
        /// The payload.
        request: Vec<u8>,
        /// Where the request id goes.
        reply: oneshot::Sender<Option<RequestId>>,
    },
    /// Answer an application request.
    TalkResponse {
        /// The peer.
        node: NodeId,
        /// The peer's endpoint.
        addr: SocketAddr,
        /// The request answered.
        request_id: RequestId,
        /// The payload.
        response: Vec<u8>,
    },
    /// Start a lookup.
    Lookup {
        /// The id searched for.
        target: NodeId,
        /// The condition results must meet.
        filter: EnrFilter,
        /// Most results.
        wanted: usize,
        /// Where the lookup id goes.
        reply: oneshot::Sender<LookupId>,
    },
    /// Replace the local record.
    SetLocalEnr(Enr, oneshot::Sender<Result<(), ServiceError>>),
    /// Report the routing table's records.
    TableEntries(oneshot::Sender<Vec<Enr>>),
    /// Stop the driver.
    Shutdown,
}

/// One input of the driver loop.
#[derive(Debug)]
pub(crate) enum Input {
    /// A datagram from the socket.
    Datagram(SocketAddr, Vec<u8>),
    /// A command from the handle, boxed since commands carry records.
    Command(Box<Command>),
}
