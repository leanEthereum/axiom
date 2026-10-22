//! A UDP payload and where it goes.

use std::net::SocketAddr;

/// One datagram for the driver to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    /// The destination endpoint.
    pub to: SocketAddr,
    /// The packet bytes.
    pub bytes: Vec<u8>,
}
