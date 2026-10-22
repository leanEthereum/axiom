//! The swarm task: owns the router and the request tables, and routes between connections and the node.

use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use tokio::{
    net::{TcpListener, TcpStream},
    spawn,
    sync::mpsc::{self, error::TrySendError},
    task::AbortHandle,
    time::{Instant, interval, sleep},
};

use super::{
    Command, InboundRequestId, NetworkConfig, NetworkEvent, RequestError, RequestId,
    connection::{self, ConnectionEvent, ConnectionId, ConnectionInput, Shared},
    events::{Admission, EventQueue},
    upgrade::upgrade,
};
use crate::{
    eth::{
        decode_gossip, encode_gossip,
        reqresp::{Protocol, RateLimiter, ResponseChunk, ResponseCode},
    },
    gossipsub::{GossipsubEvent, ProtocolVersion, Router, ValidationOutcome},
    identify::{self, IdentifyInfo},
    identity::PeerId,
    multiaddr::{Multiaddr, Protocol as AddrProtocol},
    ping,
    secure::{Role, SecurityUpgrade},
    yamux::{Mode, StreamId},
};

/// Result code for a rate-limited request: client-specific, as lighthouse uses it.
const RATE_LIMITED: ResponseCode = ResponseCode::ClientSpecific(139);

/// Inputs other than gossip that may wait for one full connection queue.
///
/// Threshold: a connection that falls this far behind is cut rather than buffered further.
const CONTROL_BACKLOG: usize = 64;

/// What became of an input for a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    /// The connection queue took it.
    Sent,
    /// The queue was full: gossip is lossy, so it was discarded.
    DroppedGossip,
    /// The queue was full: the input waits in the backlog.
    Deferred,
    /// The backlog overflowed: the connection must be cut.
    Overwhelmed,
    /// The connection is gone.
    Closed,
}

/// Everything the swarm task waits on, in one channel.
#[derive(Debug)]
pub(super) enum SwarmInput {
    /// A command from the handle.
    Command(Command),
    /// The listener accepted a socket.
    Accepted(TcpStream, SocketAddr),
    /// An outbound socket connected.
    Dialed(ConnectionId, TcpStream, Option<PeerId>),
    /// An outbound socket failed to connect.
    DialFailed(Multiaddr, String),
    /// A connection reported something.
    Connection(ConnectionId, ConnectionEvent),
    /// Time for a router heartbeat.
    Heartbeat,
    /// An outbound request ran out of time.
    RequestTimeout(RequestId),
}

/// A connection the swarm tracks.
#[derive(Debug)]
struct ConnectionEntry {
    /// The peer, once authenticated.
    peer: Option<PeerId>,
    /// The remote address.
    address: Multiaddr,
    /// Whether this node dialed.
    outbound: bool,
    /// The connection's input, once established.
    commands: Option<mpsc::Sender<ConnectionInput>>,
    /// Inputs that found the connection queue full, oldest first.
    backlog: VecDeque<ConnectionInput>,
    /// Cancels the connection task.
    task: Option<AbortHandle>,
}

impl ConnectionEntry {
    /// Hands an input to the connection without waiting, under the backpressure policy.
    fn deliver(&mut self, input: ConnectionInput) -> Delivery {
        let Some(commands) = &self.commands else {
            return Delivery::Closed;
        };
        // Order: nothing overtakes inputs already waiting in the backlog.
        let input = if self.backlog.is_empty() {
            match commands.try_send(input) {
                Ok(()) => return Delivery::Sent,
                Err(TrySendError::Closed(_)) => return Delivery::Closed,
                Err(TrySendError::Full(input)) => input,
            }
        } else {
            input
        };
        // Gossip repairs itself through IHAVE and IWANT, so it never waits.
        if matches!(input, ConnectionInput::SendGossip(_)) {
            return Delivery::DroppedGossip;
        }
        if self.backlog.len() >= CONTROL_BACKLOG {
            return Delivery::Overwhelmed;
        }
        self.backlog.push_back(input);
        Delivery::Deferred
    }

    /// Moves backlogged inputs into the connection queue while it has room.
    fn retry_backlog(&mut self) {
        let Some(commands) = &self.commands else {
            self.backlog.clear();
            return;
        };
        while let Some(input) = self.backlog.pop_front() {
            match commands.try_send(input) {
                Ok(()) => {}
                Err(TrySendError::Full(input)) => {
                    // Still full: put it back at the head and wait for the next turn.
                    self.backlog.push_front(input);
                    return;
                }
                Err(TrySendError::Closed(_)) => {
                    self.backlog.clear();
                    return;
                }
            }
        }
    }
}

/// The swarm task's state.
struct Swarm {
    /// The configuration.
    config: NetworkConfig,
    /// Settings shared with connections.
    shared: Arc<Shared>,
    /// The gossipsub router.
    router: Router,
    /// The clock origin of the router.
    start: Instant,
    /// Inbound request quotas.
    limiter: Option<RateLimiter>,
    /// Connections by identifier.
    connections: BTreeMap<ConnectionId, ConnectionEntry>,
    /// The connection serving each peer.
    peers: BTreeMap<PeerId, ConnectionId>,
    /// Outbound requests in flight, by identifier.
    requests: BTreeMap<RequestId, PeerId>,
    /// Inbound requests awaiting the node's answer.
    inbound: BTreeMap<InboundRequestId, (ConnectionId, StreamId)>,
    /// The next connection identifier.
    next_connection: u64,
    /// The next inbound request identifier.
    next_inbound: u64,
    /// The swarm's own input, for spawned tasks.
    input: mpsc::Sender<SwarmInput>,
    /// Events for the node.
    events: Arc<EventQueue>,
}

/// Spawns the swarm, accept loop, and heartbeat tasks.
pub(super) fn spawn_swarm(
    config: NetworkConfig,
    listener: TcpListener,
    listen_addr: Multiaddr,
    input: mpsc::Sender<SwarmInput>,
    mut receiver: mpsc::Receiver<SwarmInput>,
    events: Arc<EventQueue>,
) {
    let identify = IdentifyInfo {
        protocol_version: "eth2/1.0.0".to_owned(),
        agent_version: config.agent_version.clone(),
        public_key: config.identity.public_key().clone(),
        listen_addrs: vec![listen_addr],
        observed_addr: None,
        protocols: ProtocolVersion::ALL
            .iter()
            .map(|version| version.protocol_id())
            .chain(Protocol::ALL.iter().map(|protocol| protocol.protocol_id()))
            .chain([identify::PROTOCOL, ping::PROTOCOL])
            .map(str::to_owned)
            .collect(),
    };
    let shared = Arc::new(Shared {
        identify,
        max_payload_size: config.max_payload_size,
        max_gossip_frame: config.gossipsub.max_transmit_size,
        yamux: config.yamux,
        connection_queue: config.connection_queue,
    });
    let heartbeat = config.gossipsub.heartbeat_interval;
    let mut swarm = Swarm {
        router: Router::new(config.gossipsub, config.scoring.clone(), config.seed),
        limiter: config.rate_limiter.clone(),
        config,
        shared,
        start: Instant::now(),
        connections: BTreeMap::new(),
        peers: BTreeMap::new(),
        requests: BTreeMap::new(),
        inbound: BTreeMap::new(),
        next_connection: 1,
        next_inbound: 1,
        input: input.clone(),
        events,
    };

    // The accept loop feeds sockets into the swarm.
    let accept_input = input.clone();
    let accept_task = spawn(async move {
        while let Ok((stream, address)) = listener.accept().await {
            if accept_input
                .send(SwarmInput::Accepted(stream, address))
                .await
                .is_err()
            {
                return;
            }
        }
    });
    // The heartbeat ticks the router.
    let heartbeat_task = spawn(async move {
        let mut ticker = interval(heartbeat);
        // The first tick completes at once; skip it so the first heartbeat waits a full period.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if input.send(SwarmInput::Heartbeat).await.is_err() {
                return;
            }
        }
    });
    spawn(async move {
        while let Some(input) = receiver.recv().await {
            if !swarm.handle(input) {
                break;
            }
            swarm.flush_router();
            swarm.retry_backlogs();
        }
        // Shutdown: close every connection, cutting those too busy to hear it.
        for entry in swarm.connections.values_mut() {
            if entry.deliver(ConnectionInput::Close) != Delivery::Sent
                && let Some(task) = &entry.task
            {
                task.abort();
            }
        }
        swarm.events.finish();
        accept_task.abort();
        heartbeat_task.abort();
    });
}

impl Swarm {
    /// The router clock: time since the swarm started.
    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    /// Emits a control event to the node; a dropped receiver is not an error.
    fn emit(&self, event: NetworkEvent) {
        self.events.push_control(event);
    }

    /// Handles one input, returning false on shutdown.
    fn handle(&mut self, input: SwarmInput) -> bool {
        match input {
            SwarmInput::Command(Command::Shutdown) => return false,
            SwarmInput::Command(command) => self.handle_command(command),
            SwarmInput::Accepted(stream, address) => {
                let id = self.new_connection(Multiaddr::from_tcp(address), false);
                self.start_connection(id, stream, Role::Responder, None);
            }
            SwarmInput::Dialed(id, stream, expected) => {
                self.start_connection(id, stream, Role::Initiator, expected);
            }
            SwarmInput::DialFailed(address, error) => {
                self.emit(NetworkEvent::ConnectionFailed { address, error });
            }
            SwarmInput::Connection(id, event) => self.handle_connection_event(id, event),
            SwarmInput::Heartbeat => {
                let now = self.now();
                self.router.heartbeat(now);
                if let Some(limiter) = &mut self.limiter {
                    limiter.prune(now);
                }
            }
            SwarmInput::RequestTimeout(request) => {
                if let Some(peer) = self.requests.remove(&request) {
                    self.send_to_peer(&peer, ConnectionInput::CancelRequest(request));
                    self.emit(NetworkEvent::RequestFailed {
                        request,
                        peer,
                        error: RequestError::Timeout,
                    });
                }
            }
        }
        true
    }

    /// Applies a command from the node.
    fn handle_command(&mut self, command: Command) {
        let now = self.now();
        match command {
            Command::Dial(address) => self.dial(address),
            Command::Subscribe(topic) => {
                self.router.subscribe(&topic, now);
            }
            Command::Unsubscribe(topic) => {
                self.router.unsubscribe(&topic, now);
            }
            Command::Publish { topic, ssz, reply } => {
                // Gossip carries raw snappy blocks.
                let outcome = self.router.publish(topic, encode_gossip(&ssz), now);
                let _ = reply.send(outcome);
            }
            Command::Validate { id, outcome } => {
                self.router.report_validation(&id, outcome, now);
            }
            Command::Request {
                id,
                peer,
                protocol,
                payload,
            } => {
                if !self.peers.contains_key(&peer) {
                    self.emit(NetworkEvent::RequestFailed {
                        request: id,
                        peer,
                        error: RequestError::NotConnected,
                    });
                    return;
                }
                self.requests.insert(id, peer.clone());
                self.send_to_peer(&peer, ConnectionInput::SendRequest(id, protocol, payload));
                // RESP_TIMEOUT: the whole response must complete in time.
                let input = self.input.clone();
                let timeout = self.config.request_timeout;
                spawn(async move {
                    sleep(timeout).await;
                    let _ = input.send(SwarmInput::RequestTimeout(id)).await;
                });
            }
            Command::Respond { id, chunks } => {
                if let Some((connection, stream)) = self.inbound.remove(&id) {
                    self.send_to_connection(connection, ConnectionInput::Respond(stream, chunks));
                }
            }
            Command::Disconnect(peer) => self.send_to_peer(&peer, ConnectionInput::Close),
            Command::Shutdown => {}
        }
    }

    /// Starts dialing an address in the background.
    fn dial(&mut self, address: Multiaddr) {
        let Some(socket) = address.tcp_socket_addr() else {
            self.emit(NetworkEvent::ConnectionFailed {
                address,
                error: "not a TCP address".to_owned(),
            });
            return;
        };
        // Do not dial a peer already connected.
        let expected = address.peer_id().cloned();
        if expected
            .as_ref()
            .is_some_and(|peer| self.peers.contains_key(peer))
        {
            return;
        }
        // Connections are keyed by socket address; the identity layer is checked in the handshake.
        let id = self.new_connection(Multiaddr::from_tcp(socket), true);
        let input = self.input.clone();
        spawn(async move {
            let event = match TcpStream::connect(socket).await {
                Ok(stream) => SwarmInput::Dialed(id, stream, expected),
                Err(error) => SwarmInput::DialFailed(address, error.to_string()),
            };
            let _ = input.send(event).await;
        });
    }

    /// Registers a connection and returns its identifier.
    fn new_connection(&mut self, address: Multiaddr, outbound: bool) -> ConnectionId {
        let id = ConnectionId(self.next_connection);
        self.next_connection += 1;
        self.connections.insert(
            id,
            ConnectionEntry {
                peer: None,
                address,
                outbound,
                commands: None,
                backlog: VecDeque::new(),
                task: None,
            },
        );
        id
    }

    /// Spawns the task that upgrades and then runs a connection.
    fn start_connection(
        &mut self,
        id: ConnectionId,
        stream: TcpStream,
        role: Role,
        expected: Option<PeerId>,
    ) {
        let security: Arc<dyn SecurityUpgrade> = Arc::clone(&self.config.security);
        let shared = Arc::clone(&self.shared);
        let input = self.input.clone();
        let remote = self
            .connections
            .get(&id)
            .map(|entry| entry.address.clone())
            .unwrap_or_default();
        let task = spawn(async move {
            let _ = stream.set_nodelay(true);
            match upgrade(stream, role, security.as_ref(), expected).await {
                Ok(upgraded) => {
                    let mode = match role {
                        Role::Initiator => Mode::Client,
                        Role::Responder => Mode::Server,
                    };
                    connection::run(id, upgraded, mode, remote, shared, input).await;
                }
                Err(error) => {
                    let _ = input
                        .send(SwarmInput::Connection(
                            id,
                            ConnectionEvent::Failed(error.to_string()),
                        ))
                        .await;
                }
            }
        });
        if let Some(entry) = self.connections.get_mut(&id) {
            entry.task = Some(task.abort_handle());
        }
    }

    /// Applies an event from a connection.
    fn handle_connection_event(&mut self, id: ConnectionId, event: ConnectionEvent) {
        let now = self.now();
        let peer = self
            .connections
            .get(&id)
            .and_then(|entry| entry.peer.clone());
        match event {
            ConnectionEvent::Failed(error) => {
                if let Some(entry) = self.connections.remove(&id) {
                    self.emit(NetworkEvent::ConnectionFailed {
                        address: entry.address,
                        error,
                    });
                }
            }
            ConnectionEvent::Established { peer, commands } => {
                self.on_established(id, peer, commands);
            }
            ConnectionEvent::Closed => self.on_closed(id),
            // Everything below needs an authenticated, current connection.
            event => {
                let Some(peer) = peer.filter(|peer| self.peers.get(peer) == Some(&id)) else {
                    return;
                };
                match event {
                    ConnectionEvent::GossipVersion(version) => {
                        self.router.set_peer_version(&peer, version);
                    }
                    ConnectionEvent::GossipRpc(rpc) => self.router.handle_rpc(&peer, rpc, now),
                    ConnectionEvent::InboundRequest {
                        stream,
                        protocol,
                        payload,
                    } => {
                        self.on_inbound_request(id, &peer, stream, protocol, payload);
                    }
                    ConnectionEvent::ResponseChunk(request, chunk) => {
                        if self.requests.contains_key(&request) {
                            self.emit(NetworkEvent::Response {
                                request,
                                peer,
                                chunk,
                            });
                        }
                    }
                    ConnectionEvent::ResponseEnded(request) => {
                        if self.requests.remove(&request).is_some() {
                            self.emit(NetworkEvent::ResponseEnded { request, peer });
                        }
                    }
                    ConnectionEvent::RequestFailed(request, error) => {
                        if self.requests.remove(&request).is_some() {
                            self.emit(NetworkEvent::RequestFailed {
                                request,
                                peer,
                                error,
                            });
                        }
                    }
                    ConnectionEvent::Identified(info) => {
                        // The announced key must match the authenticated identity.
                        if PeerId::from_public_key(&info.public_key) == peer {
                            self.emit(NetworkEvent::PeerIdentified { peer, info });
                        }
                    }
                    ConnectionEvent::Failed(_)
                    | ConnectionEvent::Established { .. }
                    | ConnectionEvent::Closed => {}
                }
            }
        }
    }

    /// Admits an authenticated connection, unless the peer is already connected.
    fn on_established(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        commands: mpsc::Sender<ConnectionInput>,
    ) {
        // One connection per peer: the later one is closed.
        // Its queue is fresh and empty, so the close always fits.
        if self.peers.contains_key(&peer) {
            let _ = commands.try_send(ConnectionInput::Close);
            self.connections.remove(&id);
            return;
        }
        let Some(entry) = self.connections.get_mut(&id) else {
            let _ = commands.try_send(ConnectionInput::Close);
            return;
        };
        entry.peer = Some(peer.clone());
        entry.commands = Some(commands);
        let (address, outbound) = (entry.address.clone(), entry.outbound);
        self.peers.insert(peer.clone(), id);
        // The gossip revision is refined once the gossip stream settles; v1.1 is the Ethereum floor.
        self.router.add_peer(&peer, ProtocolVersion::V1_1, outbound);
        if let Some(AddrProtocol::Ip4(ip)) = address.protocols().first() {
            self.router.set_peer_ip(&peer, (*ip).into());
        }
        self.emit(NetworkEvent::PeerConnected {
            peer,
            address,
            outbound,
        });
    }

    /// Forgets a closed connection and everything attached to it.
    fn on_closed(&mut self, id: ConnectionId) {
        let Some(entry) = self.connections.remove(&id) else {
            return;
        };
        let Some(peer) = entry.peer else {
            return;
        };
        if self.peers.get(&peer) != Some(&id) {
            return;
        }
        self.peers.remove(&peer);
        let now = self.now();
        self.router.remove_peer(&peer, now);
        if let Some(limiter) = &mut self.limiter {
            limiter.remove_peer(&peer);
        }
        self.inbound.retain(|_, (connection, _)| *connection != id);
        // Requests to this peer can no longer complete.
        let failed: Vec<RequestId> = self
            .requests
            .iter()
            .filter(|(_, p)| **p == peer)
            .map(|(r, _)| *r)
            .collect();
        for request in failed {
            self.requests.remove(&request);
            self.emit(NetworkEvent::RequestFailed {
                request,
                peer: peer.clone(),
                error: RequestError::StreamClosed,
            });
        }
        self.emit(NetworkEvent::PeerDisconnected { peer });
    }

    /// Passes an inbound request to the node, unless it is over quota.
    fn on_inbound_request(
        &mut self,
        id: ConnectionId,
        peer: &PeerId,
        stream: StreamId,
        protocol: Protocol,
        payload: Vec<u8>,
    ) {
        let now = self.now();
        if let Some(limiter) = &mut self.limiter {
            let cost = request_cost(protocol, &payload);
            if limiter.allow(peer, protocol, cost, now).is_err() {
                let chunk = ResponseChunk::error(RATE_LIMITED, "rate limited");
                self.send_to_connection(id, ConnectionInput::Respond(stream, vec![chunk]));
                return;
            }
        }
        let request = InboundRequestId(self.next_inbound);
        self.next_inbound += 1;
        let event = NetworkEvent::Request {
            peer: peer.clone(),
            id: request,
            protocol,
            payload,
        };
        // Insert first, so the node never sees an identifier the swarm does not know.
        self.inbound.insert(request, (id, stream));
        let admission = self.events.push_traffic(peer, event);
        if admission != Admission::Queued {
            // The node will never see it: answer for it, then deal with the sender.
            self.inbound.remove(&request);
            let chunk = ResponseChunk::error(ResponseCode::ServerError, "busy");
            self.send_to_connection(id, ConnectionInput::Respond(stream, vec![chunk]));
            self.on_refused(peer, admission);
        }
    }

    /// Applies the flooding policy to a peer whose traffic the queue refused.
    fn on_refused(&mut self, peer: &PeerId, admission: Admission) {
        // A full queue is the node's fault and costs the peer nothing; flooding costs the connection.
        if admission == Admission::Flooding
            && let Some(&id) = self.peers.get(peer)
        {
            self.cut(id);
        }
    }

    /// Ends a connection at once, without waiting for it to drain.
    fn cut(&mut self, id: ConnectionId) {
        if let Some(task) = self
            .connections
            .get(&id)
            .and_then(|entry| entry.task.as_ref())
        {
            // Aborting drops the socket; the reader task stops with it.
            task.abort();
        }
        // The aborted task never reports its end, so the swarm records it here.
        self.on_closed(id);
    }

    /// Gives every connection backlog a chance to drain.
    fn retry_backlogs(&mut self) {
        for entry in self.connections.values_mut() {
            if !entry.backlog.is_empty() {
                entry.retry_backlog();
            }
        }
    }

    /// Delivers router output: RPCs to connections, messages to the node.
    fn flush_router(&mut self) {
        let now = self.now();
        while let Some(event) = self.router.poll_event() {
            if let GossipsubEvent::Message {
                source,
                id,
                message,
            } = event
            {
                // Gossip payloads are snappy blocks; an undecodable one is invalid outright.
                match decode_gossip(&message.data, self.config.max_payload_size) {
                    Ok(data) => {
                        let event = NetworkEvent::GossipMessage {
                            id,
                            source: source.clone(),
                            topic: message.topic,
                            data,
                        };
                        let admission = self.events.push_traffic(&source, event);
                        if admission != Admission::Queued {
                            // Unseen by the node: release it without blaming anyone.
                            self.router
                                .report_validation(&id, ValidationOutcome::Ignore, now);
                            self.on_refused(&source, admission);
                        }
                    }
                    Err(_) => {
                        self.router
                            .report_validation(&id, ValidationOutcome::Reject, now);
                    }
                }
            }
        }
        while let Some((peer, rpc)) = self.router.poll_transmit() {
            self.send_to_peer(&peer, ConnectionInput::SendGossip(rpc));
        }
    }

    /// Sends an input to the connection of a peer.
    fn send_to_peer(&mut self, peer: &PeerId, input: ConnectionInput) {
        if let Some(&id) = self.peers.get(peer) {
            self.send_to_connection(id, input);
        }
    }

    /// Sends an input to a connection without waiting, cutting it when it cannot keep up.
    fn send_to_connection(&mut self, id: ConnectionId, input: ConnectionInput) {
        let Some(entry) = self.connections.get_mut(&id) else {
            return;
        };
        if entry.deliver(input) == Delivery::Overwhelmed {
            self.cut(id);
        }
    }
}

/// Tokens a request costs: the number of items it asks for, or one.
fn request_cost(protocol: Protocol, payload: &[u8]) -> u32 {
    // Reads a little-endian u64 at an offset.
    let read_u64 = |offset: usize| {
        payload
            .get(offset..offset + 8)
            .and_then(|bytes| bytes.try_into().ok())
            .map_or(1, u64::from_le_bytes)
    };
    let items = match protocol {
        // start_slot, then count.
        Protocol::BeaconBlocksByRangeV2
        | Protocol::BlobSidecarsByRangeV1
        | Protocol::DataColumnSidecarsByRangeV1 => read_u64(8),
        // beacon_root, then count.
        Protocol::BeaconBlocksByHeadV1 => read_u64(32),
        // Lists of 32-byte roots or 40-byte identifiers.
        Protocol::BeaconBlocksByRootV2 => payload.len() as u64 / 32,
        Protocol::BlobSidecarsByRootV1 => payload.len() as u64 / 40,
        _ => 1,
    };
    u32::try_from(items.max(1)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossipsub::Rpc;

    /// An established entry whose connection queue holds one input.
    fn entry() -> (ConnectionEntry, mpsc::Receiver<ConnectionInput>) {
        let (commands, receiver) = mpsc::channel(1);
        let entry = ConnectionEntry {
            peer: None,
            address: Multiaddr::default(),
            outbound: false,
            commands: Some(commands),
            backlog: VecDeque::new(),
            task: None,
        };
        (entry, receiver)
    }

    #[test]
    fn full_queue_drops_gossip_and_defers_control() {
        let (mut entry, mut receiver) = entry();

        // The single slot takes the first input.
        assert_eq!(entry.deliver(ConnectionInput::Close), Delivery::Sent);

        // Queue full: gossip is dropped, a request waits in the backlog.
        assert_eq!(
            entry.deliver(ConnectionInput::SendGossip(Rpc::default())),
            Delivery::DroppedGossip
        );
        assert_eq!(
            entry.deliver(ConnectionInput::CancelRequest(RequestId(7))),
            Delivery::Deferred
        );
        assert_eq!(entry.backlog.len(), 1);

        // The connection takes its input; the retry moves the request into the freed slot.
        assert!(matches!(receiver.try_recv(), Ok(ConnectionInput::Close)));
        entry.retry_backlog();
        assert!(entry.backlog.is_empty());
        assert!(matches!(
            receiver.try_recv(),
            Ok(ConnectionInput::CancelRequest(RequestId(7)))
        ));
    }

    #[test]
    fn backlog_overflow_overwhelms_the_connection() {
        let (mut entry, _receiver) = entry();
        assert_eq!(entry.deliver(ConnectionInput::Close), Delivery::Sent);

        // 64 inputs fill the backlog behind the full queue.
        for request in 0..64 {
            assert_eq!(
                entry.deliver(ConnectionInput::CancelRequest(RequestId(request))),
                Delivery::Deferred
            );
        }

        // The 65th means the connection cannot keep up.
        assert_eq!(
            entry.deliver(ConnectionInput::CancelRequest(RequestId(64))),
            Delivery::Overwhelmed
        );
    }

    #[test]
    fn closed_connection_takes_nothing() {
        let (mut entry, receiver) = entry();
        drop(receiver);
        assert_eq!(entry.deliver(ConnectionInput::Close), Delivery::Closed);
    }
}
