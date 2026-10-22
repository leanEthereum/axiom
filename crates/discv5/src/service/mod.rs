//! The discovery protocol as a pure, synchronous state machine.
//!
//! # Overview
//!
//! The service never touches a socket or a clock.
//! The driver feeds it datagrams, the current time, and timer expiries.
//! It hands back datagrams to send and events to report.
//!
//! ```text
//!   datagram, now ──▶ ┌──────────────────────────────┐ ──▶ datagrams to send
//!   timer, now    ──▶ │ service                      │
//!   commands      ──▶ │   lookups, table, liveness   │ ──▶ events
//!                     │   handler: sessions, packets │
//!                     └──────────────────────────────┘
//! ```
//!
//! Equal seeds and equal inputs give equal outputs, so a simulation replays exactly.

mod config;
mod datagram;
mod error;
mod event;
mod filter;
mod handler;
mod lookup;
mod request;

use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    time::Duration,
};

use axiom_crypto::secp256k1::SecretKey;
pub use config::Config;
pub use datagram::Datagram;
pub use error::ServiceError;
pub use event::{Event, Output};
pub use filter::EnrFilter;
use handler::{Handler, HandlerConfig, HandlerEvent};
pub use lookup::LookupId;
use lookup::{Lookup, Step};
use request::{MAX_NODES_MESSAGES, Purpose, RequestState};

use crate::{
    distance::LogDistance,
    enr::Enr,
    message::{Message, RequestId},
    node_id::NodeId,
    rng::Csprng,
    table::{InsertOutcome, RoutingTable},
};

/// Bytes of records packed into one NODES message.
///
/// A message packet spends 87 bytes on IV, header, and tag, and about 30 on the message frame.
/// The rest of the 1280-byte limit carries records; this leaves a margin.
const NODES_PAYLOAD_BUDGET: usize = 1100;

/// A discv5 node: its sessions, its routing table, and its searches.
#[derive(Debug)]
pub struct Service {
    /// The settings.
    config: Config,
    /// The packet layer.
    handler: Handler,
    /// The routing table.
    table: RoutingTable,
    /// The randomness source.
    rng: Csprng,
    /// Requests awaiting answers, by peer and request id.
    requests: BTreeMap<(NodeId, RequestId), RequestState>,
    /// Lookups running.
    lookups: BTreeMap<LookupId, Lookup>,
    /// The next lookup id.
    next_lookup: u64,
    /// The next request id.
    next_request: u64,
    /// When the next liveness check runs.
    next_ping: Duration,
    /// When the next table refresh runs.
    next_refresh: Duration,
    /// Datagrams and events not yet collected.
    outputs: VecDeque<Output>,
}

impl Service {
    /// A service for a local identity.
    ///
    /// # Arguments
    ///
    /// The seed drives every random choice: nonces, keys, and request ids.
    /// The driver seeds it from the operating system; simulations fix it.
    ///
    /// # Errors
    ///
    /// Fails when the record is not signed by the key.
    pub fn new(
        key: SecretKey,
        local_enr: Enr,
        config: Config,
        seed: [u8; 32],
    ) -> Result<Self, ServiceError> {
        // The record must name the key the handshakes prove.
        if local_enr.node_id() != NodeId::from_public_key(&key.public_key()) {
            return Err(ServiceError::KeyMismatch);
        }
        let mut rng = Csprng::from_seed(seed);
        let handler = Handler::new(
            key,
            local_enr.clone(),
            HandlerConfig {
                request_timeout: config.request_timeout,
                handshake_timeout: config.handshake_timeout,
                session_capacity: config.session_capacity,
            },
        );
        Ok(Self {
            table: RoutingTable::new(local_enr.node_id(), config.table),
            next_request: rng.next_u64(),
            next_ping: config.ping_interval,
            next_refresh: config.refresh_interval,
            config,
            handler,
            rng,
            requests: BTreeMap::new(),
            lookups: BTreeMap::new(),
            next_lookup: 0,
            outputs: VecDeque::new(),
        })
    }

    /// The local record.
    #[must_use]
    pub const fn local_enr(&self) -> &Enr {
        self.handler.local_enr()
    }

    /// Replaces the local record, which must be signed by the local key.
    ///
    /// # Errors
    ///
    /// Fails when the record belongs to another node.
    pub fn set_local_enr(&mut self, enr: Enr) -> Result<(), ServiceError> {
        if enr.node_id() != self.handler.local_id() {
            return Err(ServiceError::KeyMismatch);
        }
        self.handler.set_local_enr(enr);
        Ok(())
    }

    /// The routing table.
    #[must_use]
    pub const fn table(&self) -> &RoutingTable {
        &self.table
    }

    /// Sessions currently held.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.handler.session_count()
    }

    /// The next output, or nothing when all are collected.
    pub fn poll_output(&mut self) -> Option<Output> {
        self.outputs.pop_front()
    }

    /// When the driver should next call the timer handler.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Duration> {
        // The earliest of requests, challenges, pending entries, and maintenance.
        [
            self.handler.next_deadline(),
            self.table.next_pending_deadline(),
            Some(self.next_ping),
            Some(self.next_refresh),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Adds a known record, such as a boot node, to the table.
    pub fn add_enr(&mut self, now: Duration, enr: Enr) -> InsertOutcome {
        self.discover(now, enr)
    }

    /// Pings a node; the answer arrives as an event.
    ///
    /// Returns nothing when the record has no UDP endpoint.
    pub fn ping(&mut self, now: Duration, enr: &Enr) -> Option<RequestId> {
        self.send_ping(now, enr, Purpose::Ping)
    }

    /// Asks a node for records at given distances; the answer arrives as an event.
    pub fn find_node(
        &mut self,
        now: Duration,
        enr: &Enr,
        distances: Vec<LogDistance>,
    ) -> Option<RequestId> {
        let request_id = self.fresh_request_id();
        let message = Message::FindNode {
            request_id,
            distances,
        };
        self.send_request(now, enr, message, Purpose::FindNode)
    }

    /// Sends an application request; the answer arrives as an event.
    pub fn talk_request(
        &mut self,
        now: Duration,
        enr: &Enr,
        protocol: Vec<u8>,
        request: Vec<u8>,
    ) -> Option<RequestId> {
        let request_id = self.fresh_request_id();
        let message = Message::TalkReq {
            request_id,
            protocol,
            request,
        };
        self.send_request(now, enr, message, Purpose::Talk)
    }

    /// Answers a TALKREQ reported earlier.
    pub fn talk_response(
        &mut self,
        node: NodeId,
        addr: SocketAddr,
        request_id: RequestId,
        response: Vec<u8>,
    ) {
        let message = Message::TalkResp {
            request_id,
            response,
        };
        self.respond(node, addr, &message);
    }

    /// Starts a lookup for the records nearest a target that meet a filter.
    ///
    /// The result arrives as an event, even when the table is empty.
    pub fn lookup(
        &mut self,
        now: Duration,
        target: NodeId,
        filter: EnrFilter,
        wanted: usize,
    ) -> LookupId {
        self.start_lookup(now, target, filter, wanted, false)
    }

    /// Starts a lookup, reporting it unless the service runs it for itself.
    fn start_lookup(
        &mut self,
        now: Duration,
        target: NodeId,
        filter: EnrFilter,
        wanted: usize,
        internal: bool,
    ) -> LookupId {
        // Seeds: the nearest table entries, verified or not.
        let id = LookupId(self.next_lookup);
        self.next_lookup += 1;
        let seeds = self.table.closest(&target, self.config.lookup_breadth);
        self.lookups
            .insert(id, Lookup::new(target, filter, wanted, internal, seeds));
        self.advance_lookup(now, id);
        id
    }

    /// Processes one received datagram.
    pub fn handle_datagram(&mut self, now: Duration, from: SocketAddr, datagram: &[u8]) {
        // The handler authenticates; the service acts on what survives.
        let mut out = Vec::new();
        let table = &self.table;
        let known = |node: &NodeId| table.get(node).map(|entry| entry.enr.clone());
        let events = self
            .handler
            .receive(now, from, datagram, known, &mut self.rng, &mut out);
        self.queue_datagrams(out);
        for event in events {
            match event {
                HandlerEvent::Established { enr, addr } => self.on_established(now, enr, addr),
                HandlerEvent::Request {
                    node,
                    addr,
                    message,
                } => self.on_request(now, node, addr, message),
                HandlerEvent::Response {
                    node,
                    request,
                    message,
                } => self.on_response(now, node, &request, message),
            }
        }
    }

    /// Runs every timer due by now.
    pub fn handle_timeout(&mut self, now: Duration) {
        // Phase 1: lapsed requests fail; partial FINDNODE answers still count.
        for (node, message) in self.handler.expire(now) {
            let key = (node, message.request_id());
            let Some(state) = self.requests.remove(&key) else {
                continue;
            };
            if state.responses > 0 {
                self.finish_find_node(now, node, state);
            } else {
                self.on_failure(now, node, message.request_id(), state.purpose);
            }
        }
        self.table.expire_pending(now);

        // Phase 2: maintenance, a liveness check and a refresh lookup.
        if now >= self.next_ping {
            self.next_ping = now + self.config.ping_interval;
            if let Some(enr) = self.table.revalidation_target(&mut self.rng) {
                self.send_ping(now, &enr, Purpose::Liveness);
            }
        }
        if now >= self.next_refresh {
            self.next_refresh = now + self.config.refresh_interval;
            let target = NodeId(self.rng.bytes());
            self.start_lookup(
                now,
                target,
                EnrFilter::Any,
                self.config.lookup_breadth,
                true,
            );
        }
    }

    /// A peer completed a handshake it initiated: it joins the table.
    fn on_established(&mut self, now: Duration, enr: Enr, addr: SocketAddr) {
        // Contact from the record's own endpoint proves the record live there.
        let node = enr.node_id();
        let reachable = enr.endpoints().udp_socket() == Some(addr);
        self.discover(now, enr);
        if reachable {
            self.table.record_success(&node);
        }
    }

    /// Answers a request.
    fn on_request(&mut self, now: Duration, node: NodeId, addr: SocketAddr, message: Message) {
        match message {
            Message::Ping {
                request_id,
                enr_seq,
            } => {
                let pong = Message::Pong {
                    request_id,
                    enr_seq: self.local_enr().seq(),
                    recipient_ip: addr.ip(),
                    recipient_port: addr.port(),
                };
                self.respond(node, addr, &pong);
                self.refresh_if_stale(now, node, enr_seq);
            }
            Message::FindNode {
                request_id,
                distances,
            } => self.answer_find_node(node, addr, request_id, &distances),
            Message::TalkReq {
                request_id,
                protocol,
                request,
            } => self.emit(Event::TalkRequest {
                node,
                addr,
                request_id,
                protocol,
                request,
            }),
            // Invariant: the handler routes only requests here.
            Message::Pong { .. } | Message::Nodes { .. } | Message::TalkResp { .. } => {}
        }
    }

    /// Answers FINDNODE with verified records at the requested distances.
    fn answer_find_node(
        &mut self,
        node: NodeId,
        addr: SocketAddr,
        request_id: RequestId,
        distances: &[LogDistance],
    ) {
        // Phase 1: gather up to the limit; distance zero is the local record.
        let limit = self.config.max_nodes_response;
        let mut enrs: Vec<Enr> = Vec::new();
        let mut seen: Vec<LogDistance> = Vec::new();
        for distance in distances {
            if seen.contains(distance) {
                continue;
            }
            seen.push(*distance);
            if *distance == LogDistance::ZERO {
                enrs.push(self.local_enr().clone());
            } else {
                enrs.extend(self.table.verified_at(*distance));
            }
        }
        enrs.truncate(limit);

        // Phase 2: pack the records into messages that each fit one packet.
        let mut chunks: Vec<Vec<Enr>> = vec![Vec::new()];
        let mut used = 0;
        for enr in enrs {
            let size = enr.as_bytes().len();
            if used + size > NODES_PAYLOAD_BUDGET
                && chunks.last().is_some_and(|chunk| !chunk.is_empty())
            {
                chunks.push(Vec::new());
                used = 0;
            }
            used += size;
            if let Some(chunk) = chunks.last_mut() {
                chunk.push(enr);
            }
        }
        let total = chunks.len() as u64;
        for chunk in chunks {
            let message = Message::Nodes {
                request_id,
                total,
                enrs: chunk,
            };
            self.respond(node, addr, &message);
        }
    }

    /// Acts on a response to one of this node's requests.
    fn on_response(&mut self, now: Duration, node: NodeId, request: &Message, message: Message) {
        let key = (node, message.request_id());
        let Some(state) = self.requests.get_mut(&key) else {
            self.handler.complete(node, message.request_id());
            return;
        };
        match (request, message) {
            (
                Message::Ping { .. },
                Message::Pong {
                    request_id,
                    enr_seq,
                    recipient_ip,
                    recipient_port,
                },
            ) => {
                let purpose = state.purpose;
                self.close_request(node, request_id);
                self.table.record_success(&node);
                self.refresh_if_stale(now, node, enr_seq);
                if purpose == Purpose::Ping {
                    self.emit(Event::Pong {
                        node,
                        request_id,
                        enr_seq,
                        observed: SocketAddr::new(recipient_ip, recipient_port),
                    });
                }
            }
            (
                Message::FindNode { distances, .. },
                Message::Nodes {
                    request_id,
                    total,
                    enrs,
                },
            ) => {
                // Only records at the requested distances from the responder count.
                state.enrs.extend(
                    enrs.into_iter()
                        .filter(|enr| distances.contains(&node.log_distance(&enr.node_id()))),
                );
                state.responses += 1;
                if state.responses >= total.clamp(1, MAX_NODES_MESSAGES) {
                    if let Some(state) = self.requests.remove(&key) {
                        self.handler.complete(node, request_id);
                        self.finish_find_node(now, node, state);
                    }
                }
            }
            (
                Message::TalkReq { .. },
                Message::TalkResp {
                    request_id,
                    response,
                },
            ) => {
                self.close_request(node, request_id);
                self.table.record_success(&node);
                self.emit(Event::TalkResponse {
                    node,
                    request_id,
                    response,
                });
            }
            // A response of the wrong kind is a failed request.
            (_, message) => {
                let purpose = state.purpose;
                self.close_request(node, message.request_id());
                self.on_failure(now, node, message.request_id(), purpose);
            }
        }
    }

    /// Delivers the records a FINDNODE gathered.
    fn finish_find_node(&mut self, now: Duration, node: NodeId, state: RequestState) {
        // The peer answered, so it is live; its records join the table.
        self.table.record_success(&node);
        let local = self.handler.local_id();
        let enrs: Vec<Enr> = state
            .enrs
            .into_iter()
            .filter(|enr| enr.node_id() != local)
            .collect();
        for enr in &enrs {
            self.discover(now, enr.clone());
        }
        match state.purpose {
            Purpose::Lookup(id) => {
                if let Some(lookup) = self.lookups.get_mut(&id) {
                    for enr in enrs {
                        lookup.add(enr);
                    }
                    lookup.on_response(&node);
                }
                self.advance_lookup(now, id);
            }
            Purpose::FindNode => {
                self.emit(Event::NodesFound {
                    node,
                    request_id: state.request_id,
                    enrs,
                });
            }
            Purpose::Ping | Purpose::Talk | Purpose::Liveness | Purpose::RecordRefresh => {}
        }
    }

    /// Acts on a request that went unanswered.
    fn on_failure(&mut self, now: Duration, node: NodeId, request_id: RequestId, purpose: Purpose) {
        // Silence counts against the node; past its tolerance it leaves the table.
        self.table.record_failure(&node);
        match purpose {
            Purpose::Lookup(id) => {
                if let Some(lookup) = self.lookups.get_mut(&id) {
                    lookup.on_failure(&node);
                }
                self.advance_lookup(now, id);
            }
            Purpose::Ping | Purpose::FindNode | Purpose::Talk => {
                self.emit(Event::RequestFailed { node, request_id });
            }
            Purpose::Liveness | Purpose::RecordRefresh => {}
        }
    }

    /// Sends the next requests of a lookup, or reports it finished.
    fn advance_lookup(&mut self, now: Duration, id: LookupId) {
        let alpha = self.config.lookup_parallelism;
        let breadth = self.config.lookup_breadth;
        let per_request = self.config.lookup_distances;
        loop {
            let Some(lookup) = self.lookups.get_mut(&id) else {
                return;
            };
            let queries: Vec<(Enr, Vec<LogDistance>)> = match lookup.next(alpha, breadth) {
                Step::Wait => return,
                Step::Done => {
                    let Some(lookup) = self.lookups.remove(&id) else {
                        return;
                    };
                    if !lookup.is_internal() {
                        let peers = lookup.results(&self.config.chain);
                        self.emit(Event::LookupFinished {
                            id,
                            target: lookup.target(),
                            peers,
                        });
                    }
                    return;
                }
                Step::Query(peers) => peers
                    .into_iter()
                    .map(|peer| {
                        let distances = lookup.distances(&peer.node_id(), per_request);
                        (peer, distances)
                    })
                    .collect(),
            };
            // Each peer is asked for the buckets around the target, from its point of view.
            let mut all_sent = true;
            for (peer, distances) in queries {
                let request_id = self.fresh_request_id();
                let message = Message::FindNode {
                    request_id,
                    distances,
                };
                if self
                    .send_request(now, &peer, message, Purpose::Lookup(id))
                    .is_none()
                {
                    // An unreachable peer fails at once, which may free a slot for another.
                    all_sent = false;
                    if let Some(lookup) = self.lookups.get_mut(&id) {
                        lookup.on_failure(&peer.node_id());
                    }
                }
            }
            if all_sent {
                return;
            }
        }
    }

    /// Offers a record to the table, reporting newcomers and checking full buckets.
    fn discover(&mut self, now: Duration, enr: Enr) -> InsertOutcome {
        let outcome = self.table.insert(enr.clone(), now);
        match &outcome {
            InsertOutcome::Inserted => self.emit(Event::Discovered(enr)),
            InsertOutcome::Pending { check } => {
                let check = (**check).clone();
                self.send_ping(now, &check, Purpose::Liveness);
            }
            InsertOutcome::Updated
            | InsertOutcome::Unchanged
            | InsertOutcome::BucketFull
            | InsertOutcome::IpLimited
            | InsertOutcome::LocalNode => {}
        }
        outcome
    }

    /// Fetches a peer's record when it announces a newer one than the table holds.
    fn refresh_if_stale(&mut self, now: Duration, node: NodeId, enr_seq: u64) {
        let Some(entry) = self.table.get(&node) else {
            return;
        };
        if enr_seq <= entry.enr.seq() {
            return;
        }
        // FINDNODE at distance zero returns the peer's own record.
        let enr = entry.enr.clone();
        let request_id = self.fresh_request_id();
        let message = Message::FindNode {
            request_id,
            distances: vec![LogDistance::ZERO],
        };
        self.send_request(now, &enr, message, Purpose::RecordRefresh);
    }

    /// Sends a PING with the local sequence number.
    fn send_ping(&mut self, now: Duration, enr: &Enr, purpose: Purpose) -> Option<RequestId> {
        let request_id = self.fresh_request_id();
        let message = Message::Ping {
            request_id,
            enr_seq: self.local_enr().seq(),
        };
        self.send_request(now, enr, message, purpose)
    }

    /// Sends a request and remembers why.
    fn send_request(
        &mut self,
        now: Duration,
        enr: &Enr,
        message: Message,
        purpose: Purpose,
    ) -> Option<RequestId> {
        let request_id = message.request_id();
        let mut out = Vec::new();
        let sent = self
            .handler
            .send_request(now, enr, message, &mut self.rng, &mut out);
        self.queue_datagrams(out);
        if !sent {
            return None;
        }
        self.requests.insert(
            (enr.node_id(), request_id),
            RequestState::new(purpose, request_id),
        );
        Some(request_id)
    }

    /// Sends a response through the handler.
    fn respond(&mut self, node: NodeId, addr: SocketAddr, message: &Message) {
        let mut out = Vec::new();
        self.handler
            .send_response(node, addr, message, &mut self.rng, &mut out);
        self.queue_datagrams(out);
    }

    /// Forgets a request in both layers.
    fn close_request(&mut self, node: NodeId, request_id: RequestId) {
        self.requests.remove(&(node, request_id));
        self.handler.complete(node, request_id);
    }

    /// A request id not used before by this service.
    fn fresh_request_id(&mut self) -> RequestId {
        // A counter from a random start: unique locally, unpredictable to peers.
        let id = RequestId::from_u64(self.next_request);
        self.next_request = self.next_request.wrapping_add(1);
        id
    }

    /// Queues datagrams for the driver.
    fn queue_datagrams(&mut self, datagrams: Vec<Datagram>) {
        self.outputs.extend(datagrams.into_iter().map(Output::Send));
    }

    /// Queues an event for the driver.
    fn emit(&mut self, event: Event) {
        self.outputs.push_back(Output::Event(event));
    }
}
