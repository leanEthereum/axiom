//! The tokio adapter: TCP connections, upgrades, and one task per connection.
//!
//! # Overview
//!
//! The node talks to the network through two halves.
//!
//! - A handle sends commands: dial, publish, subscribe, request, respond, disconnect.
//! - An event stream reports peers, gossip messages, requests, and responses.
//!
//! ```text
//!                      ┌──────────── swarm task ────────────┐
//! handle ── command ──▶│ gossipsub router, request tables   │── event ──▶ node
//!                      └──▲──────────────┬──────────────────┘
//!                         │ events       │ commands
//!                ┌────────┴──────────────▼────────┐
//!                │ connection task, one per peer  │◀── reader task: socket → plaintext
//!                │ yamux session, stream handlers │──▶ socket: sealed frames
//!                └────────────────────────────────┘
//! ```
//!
//! Every task waits on a single channel, so no task ever selects over several futures.
//! The swarm task owns the router; its clock is the time since the swarm started.
//!
//! # Backpressure
//!
//! Every queue is bounded, and each bound has one policy.
//!
//! ```text
//! socket ──▶ reader task ══▶ connection task ══▶ swarm task ──▶ event queue ──▶ node
//!                        waits              waits          never waits
//!
//! ══▶  bounded channel; a full one makes the sender wait
//! ```
//!
//! - The reader waits for its connection, so a slow connection stops reading the socket.
//! - A connection grants yamux credit only once the swarm took the data.
//!   A peer that outpaces the node therefore stalls at its yamux window, then at TCP.
//! - The swarm never waits: it must keep serving every other peer.
//!   - Gossip for a connection whose queue is full is dropped; gossipsub repairs the gap.
//!   - Other input waits in a short per-connection backlog.
//!     When that overflows, the connection is cut.
//! - Events for the node are bounded per peer and in all; see the events module.

mod connection;
mod driver;
mod events;
mod upgrade;

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

pub use events::{EventLimits, NetworkEvents};
use thiserror::Error;
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
};

use crate::{
    eth::{
        MAX_PAYLOAD_SIZE,
        reqresp::{Protocol, RateLimiter, ResponseChunk},
    },
    gossipsub::{
        GossipsubConfig, MessageId, PeerScoreParams, PeerScoreThresholds, PublishError, Topic,
        ValidationOutcome,
    },
    identify::IdentifyInfo,
    identity::{Keypair, PeerId},
    multiaddr::{Multiaddr, MultiaddrError},
    multistream::NegotiationError,
    secure::{SecureError, SecurityUpgrade, noise::NoiseConfig},
    yamux,
};

/// Everything the swarm needs to start.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// The local secp256k1 identity, which names this node and signs its handshakes.
    pub identity: Keypair,
    /// The TCP address to listen on; port zero picks a free port.
    pub listen_addr: Multiaddr,
    /// The security protocol: Noise, or plaintext in tests.
    pub security: Arc<dyn SecurityUpgrade>,
    /// Gossipsub parameters.
    pub gossipsub: GossipsubConfig,
    /// Peer scoring parameters, or nothing to disable scoring.
    pub scoring: Option<(PeerScoreParams, PeerScoreThresholds)>,
    /// Yamux parameters.
    pub yamux: yamux::Config,
    /// MAX_PAYLOAD_SIZE, for gossip and req/resp.
    pub max_payload_size: u64,
    /// The agent string announced through identify.
    pub agent_version: String,
    /// Inbound request quotas, or nothing to serve every request.
    pub rate_limiter: Option<RateLimiter>,
    /// Time an outbound request may take before it fails.
    pub request_timeout: Duration,
    /// Seed of the router's peer selection.
    pub seed: u64,
    /// Bounds on peer traffic waiting for the node.
    pub event_limits: EventLimits,
    /// Inputs one connection task holds before its senders wait or drop.
    pub connection_queue: usize,
    /// Inputs the swarm task holds before connections and the handle wait.
    pub swarm_queue: usize,
}

impl NetworkConfig {
    /// A configuration with mainnet parameters, Noise, and an ephemeral localhost port.
    ///
    /// # Errors
    ///
    /// Fails when the operating system cannot supply entropy for the Noise keys.
    pub fn new(identity: Keypair) -> Result<Self, NetworkError> {
        let security = Arc::new(NoiseConfig::new(&identity)?);
        Ok(Self::with_security(identity, security))
    }

    /// A configuration with mainnet parameters and a chosen security protocol.
    #[must_use]
    pub fn with_security(identity: Keypair, security: Arc<dyn SecurityUpgrade>) -> Self {
        Self {
            identity,
            listen_addr: Multiaddr::from_tcp(([127, 0, 0, 1], 0).into()),
            security,
            gossipsub: GossipsubConfig::default(),
            scoring: None,
            yamux: yamux::Config::default(),
            max_payload_size: MAX_PAYLOAD_SIZE,
            agent_version: concat!("axiom/", env!("CARGO_PKG_VERSION")).to_owned(),
            rate_limiter: None,
            // RESP_TIMEOUT of the phase0 p2p-interface configuration: 10 seconds.
            request_timeout: Duration::from_secs(10),
            seed: 0,
            event_limits: EventLimits::default(),
            // Threshold: 64 reads of up to 64 KiB, so at most 4 MiB of plaintext per connection.
            connection_queue: 64,
            swarm_queue: 1024,
        }
    }
}

/// Identifies an outbound request, chosen by the handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(pub u64);

/// Identifies an inbound request awaiting a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InboundRequestId(pub u64);

/// Why an outbound request ended without a complete response.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RequestError {
    /// The peer is not connected.
    #[error("peer not connected")]
    NotConnected,
    /// The peer does not support the protocol.
    #[error("protocol not supported by the peer")]
    Unsupported,
    /// The response was malformed.
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    /// The stream was reset or the connection dropped.
    #[error("stream closed before the response completed")]
    StreamClosed,
    /// The response did not complete in time.
    #[error("response timed out")]
    Timeout,
}

/// Something that happened on the network.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum NetworkEvent {
    /// A connection completed its upgrade.
    PeerConnected {
        /// The authenticated peer.
        peer: PeerId,
        /// The remote socket address.
        address: Multiaddr,
        /// Whether this node dialed.
        outbound: bool,
    },
    /// A connection closed.
    PeerDisconnected {
        /// The peer.
        peer: PeerId,
    },
    /// A dial or an inbound upgrade failed.
    ConnectionFailed {
        /// The remote address.
        address: Multiaddr,
        /// What went wrong.
        error: String,
    },
    /// A gossip message awaits validation.
    ///
    /// The node must answer through the handle with a validation outcome.
    GossipMessage {
        /// The message identifier.
        id: MessageId,
        /// The peer that delivered it first.
        source: PeerId,
        /// The topic.
        topic: Topic,
        /// The decompressed SSZ payload.
        data: Vec<u8>,
    },
    /// A peer sent a request; the node must respond through the handle.
    Request {
        /// The requesting peer.
        peer: PeerId,
        /// The handle to respond with.
        id: InboundRequestId,
        /// The method.
        protocol: Protocol,
        /// The decompressed SSZ request.
        payload: Vec<u8>,
    },
    /// A response chunk arrived for an outbound request.
    Response {
        /// The request.
        request: RequestId,
        /// The responding peer.
        peer: PeerId,
        /// The chunk.
        chunk: ResponseChunk,
    },
    /// An outbound request completed.
    ResponseEnded {
        /// The request.
        request: RequestId,
        /// The responding peer.
        peer: PeerId,
    },
    /// An outbound request failed.
    RequestFailed {
        /// The request.
        request: RequestId,
        /// The peer.
        peer: PeerId,
        /// What went wrong.
        error: RequestError,
    },
    /// A peer described itself through identify.
    PeerIdentified {
        /// The peer.
        peer: PeerId,
        /// Its self-description.
        info: IdentifyInfo,
    },
}

/// A failure of the swarm or of one connection.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NetworkError {
    /// A socket operation failed.
    #[error("i/o error: {0}")]
    Io(io::Error),
    /// The address is not a TCP address.
    #[error("unsupported address {0}")]
    UnsupportedAddress(Multiaddr),
    /// The address is malformed.
    #[error("invalid address: {0}")]
    InvalidAddress(MultiaddrError),
    /// A protocol negotiation failed.
    #[error("negotiation failed: {0}")]
    Negotiation(NegotiationError),
    /// The security handshake failed.
    #[error("security handshake failed: {0}")]
    Security(SecureError),
    /// The peer closed the connection.
    #[error("connection closed")]
    ConnectionClosed,
    /// The swarm task has stopped.
    #[error("network has shut down")]
    Shutdown,
}

impl From<io::Error> for NetworkError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<NegotiationError> for NetworkError {
    fn from(error: NegotiationError) -> Self {
        Self::Negotiation(error)
    }
}

impl From<SecureError> for NetworkError {
    fn from(error: SecureError) -> Self {
        Self::Security(error)
    }
}

impl From<MultiaddrError> for NetworkError {
    fn from(error: MultiaddrError) -> Self {
        Self::InvalidAddress(error)
    }
}

/// A command from the handle to the swarm task.
#[derive(Debug)]
enum Command {
    /// Dial an address.
    Dial(Multiaddr),
    /// Join a topic.
    Subscribe(Topic),
    /// Leave a topic.
    Unsubscribe(Topic),
    /// Publish an SSZ payload, compressed by the swarm.
    Publish {
        /// The topic.
        topic: Topic,
        /// The SSZ payload.
        ssz: Vec<u8>,
        /// Where the outcome goes.
        reply: oneshot::Sender<Result<MessageId, PublishError>>,
    },
    /// The verdict on a gossip message.
    Validate {
        /// The message.
        id: MessageId,
        /// The verdict.
        outcome: ValidationOutcome,
    },
    /// Send a request.
    Request {
        /// The identifier the handle chose.
        id: RequestId,
        /// The peer.
        peer: PeerId,
        /// The method.
        protocol: Protocol,
        /// The SSZ request.
        payload: Vec<u8>,
    },
    /// Answer an inbound request with chunks, then close its stream.
    Respond {
        /// The request.
        id: InboundRequestId,
        /// The chunks, in order.
        chunks: Vec<ResponseChunk>,
    },
    /// Close the connection to a peer.
    Disconnect(PeerId),
    /// Stop everything.
    Shutdown,
}

/// The node's way to drive the network.
#[derive(Clone, Debug)]
pub struct NetworkHandle {
    /// The swarm task's input.
    commands: mpsc::Sender<driver::SwarmInput>,
    /// The local identity.
    local_peer: PeerId,
    /// The bound listen address.
    listen_addr: Multiaddr,
    /// The next outbound request identifier.
    next_request: Arc<AtomicU64>,
}

impl NetworkHandle {
    /// The local identity.
    #[must_use]
    pub const fn local_peer(&self) -> &PeerId {
        &self.local_peer
    }

    /// The bound listen address, with the actual port.
    #[must_use]
    pub const fn listen_addr(&self) -> &Multiaddr {
        &self.listen_addr
    }

    /// Dials a TCP address; a trailing peer layer is checked during the handshake.
    pub async fn dial(&self, address: Multiaddr) -> Result<(), NetworkError> {
        self.send(Command::Dial(address)).await
    }

    /// Joins a gossip topic.
    pub async fn subscribe(&self, topic: Topic) -> Result<(), NetworkError> {
        self.send(Command::Subscribe(topic)).await
    }

    /// Leaves a gossip topic.
    pub async fn unsubscribe(&self, topic: Topic) -> Result<(), NetworkError> {
        self.send(Command::Unsubscribe(topic)).await
    }

    /// Publishes an SSZ payload; the network compresses it.
    ///
    /// # Returns
    ///
    /// The router's verdict: the message identifier, or why nothing was sent.
    pub async fn publish(
        &self,
        topic: Topic,
        ssz: Vec<u8>,
    ) -> Result<Result<MessageId, PublishError>, NetworkError> {
        let (reply, outcome) = oneshot::channel();
        self.send(Command::Publish { topic, ssz, reply }).await?;
        outcome.await.map_err(|_| NetworkError::Shutdown)
    }

    /// Reports the verdict on a gossip message.
    pub async fn report_validation(
        &self,
        id: MessageId,
        outcome: ValidationOutcome,
    ) -> Result<(), NetworkError> {
        self.send(Command::Validate { id, outcome }).await
    }

    /// Sends a request; chunks and the outcome arrive as events tagged with the returned identifier.
    pub async fn send_request(
        &self,
        peer: PeerId,
        protocol: Protocol,
        payload: Vec<u8>,
    ) -> Result<RequestId, NetworkError> {
        let id = RequestId(self.next_request.fetch_add(1, Ordering::Relaxed));
        self.send(Command::Request {
            id,
            peer,
            protocol,
            payload,
        })
        .await?;
        Ok(id)
    }

    /// Answers an inbound request; the stream closes after the last chunk.
    pub async fn respond(
        &self,
        id: InboundRequestId,
        chunks: Vec<ResponseChunk>,
    ) -> Result<(), NetworkError> {
        self.send(Command::Respond { id, chunks }).await
    }

    /// Closes the connection to a peer.
    pub async fn disconnect(&self, peer: PeerId) -> Result<(), NetworkError> {
        self.send(Command::Disconnect(peer)).await
    }

    /// Stops the swarm and every connection.
    pub async fn shutdown(&self) -> Result<(), NetworkError> {
        self.send(Command::Shutdown).await
    }

    /// Hands a command to the swarm task, waiting while its queue is full.
    async fn send(&self, command: Command) -> Result<(), NetworkError> {
        self.commands
            .send(driver::SwarmInput::Command(command))
            .await
            .map_err(|_| NetworkError::Shutdown)
    }
}

/// Starts the network: binds the listener and spawns the swarm.
///
/// Must be called from within a tokio runtime.
pub async fn start(config: NetworkConfig) -> Result<(NetworkHandle, NetworkEvents), NetworkError> {
    let socket = config
        .listen_addr
        .tcp_socket_addr()
        .ok_or_else(|| NetworkError::UnsupportedAddress(config.listen_addr.clone()))?;
    let listener = TcpListener::bind(socket).await?;
    let listen_addr = Multiaddr::from_tcp(listener.local_addr()?);
    let local_peer = config.identity.peer_id();
    let (input_tx, input_rx) = mpsc::channel(config.swarm_queue.max(1));
    let queue = events::EventQueue::new(config.event_limits);
    driver::spawn_swarm(
        config,
        listener,
        listen_addr.clone(),
        input_tx.clone(),
        input_rx,
        Arc::clone(&queue),
    );
    let handle = NetworkHandle {
        commands: input_tx,
        local_peer,
        listen_addr,
        next_request: Arc::new(AtomicU64::new(1)),
    };
    Ok((handle, NetworkEvents::new(queue)))
}
