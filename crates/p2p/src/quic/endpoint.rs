//! Many connections on one UDP socket: routing datagrams by connection id.
//!
//! # Overview
//!
//! Every connection this endpoint makes is addressed by an 8-byte id it chose at random.
//! A datagram goes to the connection its first packet's destination id names.
//!
//! A server-side connection starts on a client Initial of at least 1200 bytes with an unknown id.
//! Until the client learns the server's id, its packets carry the id it picked itself.
//! So the endpoint routes both ids to the new connection.
//!
//! A long header of an unknown version is answered with Version Negotiation, per RFC 9000, section 6.
//! Anything else unknown is dropped.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use super::{
    Connection, ConnectionId, QuicConfig, Transmit, VERSION,
    connection::{ConnectionSetup, LOCAL_CID_LEN},
    packet::{FIXED_BIT, Header, LONG_FORM, LongType, ProtectedPacket},
};
use crate::{Entropy, identity::PeerId};

/// The smallest datagram that may open a connection or earn a Version Negotiation reply.
///
/// RFC 9000, sections 14.1 and 6.1: answering smaller datagrams would amplify attacks.
const MIN_INITIAL_DATAGRAM: usize = 1200;

/// The shortest destination id a client may pick for its first Initial, per RFC 9000, section 7.2.
const MIN_CLIENT_DCID: usize = 8;

/// Names a connection within its endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionHandle(pub u64);

/// What to do with a datagram.
#[derive(Debug)]
pub enum DatagramEvent {
    /// Hand it to an existing connection.
    Route(ConnectionHandle),
    /// A client opened a connection, which already took the datagram in.
    Accept(ConnectionHandle, Box<Connection>),
    /// Send this reply; no connection is involved.
    Respond(Transmit),
}

/// The routing table of a socket's connections.
#[derive(Debug)]
pub struct Endpoint {
    /// Settings every connection shares.
    config: Arc<QuicConfig>,
    /// Randomness for ids and TLS secrets.
    entropy: Entropy,
    /// Connections by the ids that address them.
    routes: HashMap<ConnectionId, ConnectionHandle>,
    /// The ids routed to each connection, for removal.
    ids: HashMap<ConnectionHandle, Vec<ConnectionId>>,
    /// The next handle.
    next_handle: u64,
    /// Whether inbound connections are accepted.
    accepting: bool,
}

impl Endpoint {
    /// An endpoint with no connections.
    ///
    /// # Arguments
    ///
    /// - `seed`: 32 bytes of operating system entropy.
    #[must_use]
    pub fn new(config: Arc<QuicConfig>, seed: [u8; 32]) -> Self {
        Self {
            config,
            entropy: Entropy::new(seed),
            routes: HashMap::new(),
            ids: HashMap::new(),
            next_handle: 0,
            accepting: true,
        }
    }

    /// Stops or resumes accepting inbound connections.
    pub const fn set_accepting(&mut self, accepting: bool) {
        self.accepting = accepting;
    }

    /// Connections the endpoint routes to.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether no connection is routed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Starts a client connection.
    ///
    /// # Arguments
    ///
    /// - `expected`: the peer the dialer means to reach, if known.
    /// - `now`: the connection clock.
    /// - `unix_seconds`: the wall clock, for certificate validity.
    pub fn connect(
        &mut self,
        remote: SocketAddr,
        expected: Option<PeerId>,
        now: Duration,
        unix_seconds: u64,
    ) -> (ConnectionHandle, Connection) {
        let local_cid = self.fresh_cid();
        let setup = ConnectionSetup {
            config: Arc::clone(&self.config),
            local_cid,
            remote,
            now,
            unix_seconds,
        };
        let connection = Connection::client(setup, expected, &mut self.entropy);
        let handle = self.register(&[local_cid]);
        (handle, connection)
    }

    /// Routes a datagram.
    ///
    /// # Returns
    ///
    /// The connection to hand it to, a new connection, a reply, or nothing when it is dropped.
    pub fn handle(
        &mut self,
        now: Duration,
        unix_seconds: u64,
        from: SocketAddr,
        datagram: &[u8],
    ) -> Option<DatagramEvent> {
        let (packet, _) = ProtectedPacket::parse(datagram, LOCAL_CID_LEN).ok()?;
        let dcid = match &packet.header {
            Header::Long { dcid, .. }
            | Header::Retry { dcid, .. }
            | Header::Short { dcid }
            | Header::VersionNegotiation { dcid, .. } => *dcid,
            Header::UnsupportedVersion { dcid, scid, .. } => {
                return (datagram.len() >= MIN_INITIAL_DATAGRAM)
                    .then(|| DatagramEvent::Respond(self.version_negotiation(from, *dcid, *scid)));
            }
        };
        if let Some(handle) = self.routes.get(&dcid) {
            return Some(DatagramEvent::Route(*handle));
        }
        let Header::Long {
            kind: LongType::Initial,
            scid,
            ..
        } = packet.header
        else {
            return None;
        };
        if !self.accepting || datagram.len() < MIN_INITIAL_DATAGRAM || dcid.len() < MIN_CLIENT_DCID
        {
            return None;
        }
        let local_cid = self.fresh_cid();
        let setup = ConnectionSetup {
            config: Arc::clone(&self.config),
            local_cid,
            remote: from,
            now,
            unix_seconds,
        };
        let mut connection = Connection::server(setup, dcid, scid, &mut self.entropy);
        connection.handle_datagram(now, from, datagram);
        let handle = self.register(&[local_cid, dcid]);
        Some(DatagramEvent::Accept(handle, Box::new(connection)))
    }

    /// Stops routing to a connection, once it is closed.
    pub fn forget(&mut self, handle: ConnectionHandle) {
        for id in self.ids.remove(&handle).unwrap_or_default() {
            self.routes.remove(&id);
        }
    }

    /// A Version Negotiation packet listing version 1, echoing the client's ids swapped.
    fn version_negotiation(
        &mut self,
        to: SocketAddr,
        dcid: ConnectionId,
        scid: ConnectionId,
    ) -> Transmit {
        let mut bytes = Vec::with_capacity(64);
        // The low seven bits are unused and random, per RFC 9000, section 17.2.1.
        let [random] = self.entropy.array::<1>();
        bytes.push(LONG_FORM | FIXED_BIT | (random & 0x3f));
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        scid.encode_with_length(&mut bytes);
        dcid.encode_with_length(&mut bytes);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        Transmit {
            destination: to,
            bytes,
        }
    }

    /// A random id not already routed.
    fn fresh_cid(&mut self) -> ConnectionId {
        loop {
            let bytes: [u8; LOCAL_CID_LEN] = self.entropy.array();
            // Invariant: eight bytes are within the 20-byte limit.
            let id = ConnectionId::new(&bytes).unwrap_or(ConnectionId::EMPTY);
            if !self.routes.contains_key(&id) {
                return id;
            }
        }
    }

    /// Routes ids to a new handle.
    fn register(&mut self, ids: &[ConnectionId]) -> ConnectionHandle {
        let handle = ConnectionHandle(self.next_handle);
        self.next_handle += 1;
        for id in ids {
            self.routes.insert(*id, handle);
        }
        self.ids.insert(handle, ids.to_vec());
        handle
    }
}
