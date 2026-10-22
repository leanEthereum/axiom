//! A request this node sent and awaits an answer to.

use std::{net::SocketAddr, time::Duration};

use crate::{enr::Enr, message::Message, packet::Nonce};

/// Where a request stands on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// Sent in the packet with this nonce; a WHOAREYOU naming it asks for a handshake.
    Sent(Nonce),

    /// Held until a handshake already under way with the peer finishes.
    Queued,
}

/// A request awaiting its response.
#[derive(Clone, Debug)]
pub(crate) struct InFlight {
    /// The peer's record, whose key the handshake needs.
    pub(crate) contact: Enr,
    /// The peer's endpoint.
    pub(crate) addr: SocketAddr,
    /// The request, kept so it can be resent inside a handshake.
    pub(crate) message: Message,
    /// The wire state.
    pub(crate) delivery: Delivery,
    /// When the request fails.
    pub(crate) deadline: Duration,
    /// Handshakes this request has carried.
    pub(crate) handshakes: u8,
}
