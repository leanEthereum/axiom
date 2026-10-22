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
        let local_id = local_enr.node_id();
        let handler = Handler::new(
            key,
            local_enr,
            HandlerConfig {
                request_timeout: config.request_timeout,
                handshake_timeout: config.handshake_timeout,
                session_capacity: config.session_capacity,
            },
        );
        Ok(Self {
            table: RoutingTable::new(local_id, config.table),
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
                if state.responses >= total.clamp(1, MAX_NODES_MESSAGES)
                    && let Some(state) = self.requests.remove(&key)
                {
                    self.handler.complete(node, request_id);
                    self.finish_find_node(now, node, state);
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
        // The peer answered, so it is live; its records, bar the local one, join the table.
        self.table.record_success(&node);
        let local = self.handler.local_id();
        let enrs = state.enrs;
        for enr in enrs.iter().filter(|enr| enr.node_id() != local) {
            self.discover(now, enr.clone());
        }
        match state.purpose {
            Purpose::Lookup(id) => {
                if let Some(lookup) = self.lookups.get_mut(&id) {
                    for enr in enrs.into_iter().filter(|enr| enr.node_id() != local) {
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
            InsertOutcome::Inserted => self.emit(Event::Discovered(Box::new(enr))),
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
    const fn fresh_request_id(&mut self) -> RequestId {
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

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, net::Ipv4Addr};

    use super::*;
    use crate::table::TableConfig;

    /// Nodes wired back to back: datagrams arrive in send order, with no loss and no delay.
    struct Wire {
        /// The services.
        nodes: Vec<Service>,
        /// Datagrams in transit: sender index, then the datagram.
        queue: VecDeque<(usize, Datagram)>,
        /// Events per node.
        events: Vec<Vec<Event>>,
        /// Indices of datagrams to drop, counted from zero over the whole run.
        drop: Vec<usize>,
        /// Datagrams sent so far.
        sent: usize,
        /// Every datagram sent, dropped ones included.
        log: Vec<Vec<u8>>,
    }

    impl Wire {
        /// Nodes 1 to n on 10.0.i.1:9000, with a given key seed per node.
        fn new(count: u8) -> Self {
            // Node i signs with key [i; 32] and seeds its generator with [i; 32].
            let nodes = (1..=count)
                .map(|i| {
                    let enr = record(i, 1);
                    Service::new(key(i), enr, Config::default(), [i; 32]).expect("key matches")
                })
                .collect();
            Self {
                nodes,
                queue: VecDeque::new(),
                events: vec![Vec::new(); usize::from(count)],
                drop: Vec::new(),
                sent: 0,
                log: Vec::new(),
            }
        }

        /// Collects one node's outputs.
        fn drain(&mut self, node: usize) {
            // Datagrams go on the wire unless marked for dropping; events are kept per node.
            while let Some(output) = self.nodes[node].poll_output() {
                match output {
                    Output::Send(datagram) => {
                        self.log.push(datagram.bytes.clone());
                        if !self.drop.contains(&self.sent) {
                            self.queue.push_back((node, datagram));
                        }
                        self.sent += 1;
                    }
                    Output::Event(event) => self.events[node].push(event),
                }
            }
        }

        /// Delivers datagrams until none are in transit.
        fn settle(&mut self, now: Duration) {
            // First collect what every node already queued, then deliver in order.
            for node in 0..self.nodes.len() {
                self.drain(node);
            }
            while let Some((from, datagram)) = self.queue.pop_front() {
                let to = self
                    .nodes
                    .iter()
                    .position(|node| node.local_enr().endpoints().udp_socket() == Some(datagram.to))
                    .expect("known endpoint");
                let from_addr = self.nodes[from]
                    .local_enr()
                    .endpoints()
                    .udp_socket()
                    .expect("endpoint");
                self.nodes[to].handle_datagram(now, from_addr, &datagram.bytes);
                self.drain(to);
            }
        }

        /// The record of node i.
        fn enr(&self, node: usize) -> Enr {
            self.nodes[node].local_enr().clone()
        }
    }

    /// The key of node i.
    fn key(i: u8) -> SecretKey {
        SecretKey::from_bytes(&[i; 32]).expect("valid key")
    }

    /// The record of node i at a sequence number.
    fn record(i: u8, seq: u64) -> Enr {
        // Node i lives on 10.0.i.1:9000, its own /24.
        Enr::builder()
            .seq(seq)
            .ip4(Ipv4Addr::new(10, 0, i, 1))
            .udp4(9000)
            .build(&key(i))
            .expect("record fits")
    }

    #[test]
    fn records_must_match_the_key() {
        // Node 2's record with node 1's key.
        assert_eq!(
            Service::new(key(1), record(2, 1), Config::default(), [0; 32]).map(|_| ()),
            Err(ServiceError::KeyMismatch)
        );
    }

    #[test]
    fn ping_opens_a_session_in_four_packets() {
        // Packets: random opener, WHOAREYOU, handshake with PING, PONG.
        let mut wire = Wire::new(2);
        let bob = wire.enr(1);
        let request_id = wire.nodes[0]
            .ping(Duration::ZERO, &bob)
            .expect("bob has an endpoint");
        wire.settle(Duration::ZERO);
        assert_eq!(wire.sent, 4);
        assert_eq!(
            wire.events[0],
            [Event::Pong {
                node: bob.node_id(),
                request_id,
                enr_seq: 1,
                observed: wire.enr(0).endpoints().udp_socket().expect("endpoint"),
            }]
        );
        // Bob learned alice from the record in her handshake.
        assert_eq!(wire.events[1], [Event::Discovered(Box::new(wire.enr(0)))]);
        // A second ping reuses the session: two packets.
        wire.nodes[0].ping(Duration::ZERO, &bob);
        wire.settle(Duration::ZERO);
        assert_eq!(wire.sent, 6);
    }

    #[test]
    fn simultaneous_handshakes_converge() {
        // Alice and bob ping each other before either has a session.
        let mut wire = Wire::new(2);
        let alice = wire.enr(0);
        let bob = wire.enr(1);
        wire.nodes[0].ping(Duration::ZERO, &bob);
        wire.nodes[1].ping(Duration::ZERO, &alice);
        wire.settle(Duration::ZERO);
        // Each ends with a session and a PONG, whichever handshake won on each side.
        let pongs = |events: &[Event]| {
            events
                .iter()
                .filter(|event| matches!(event, Event::Pong { .. }))
                .count()
        };
        assert_eq!(pongs(&wire.events[0]), 1);
        assert_eq!(pongs(&wire.events[1]), 1);
        // Later traffic flows both ways without a new handshake: two packets per ping.
        let before = wire.sent;
        wire.nodes[0].ping(Duration::ZERO, &bob);
        wire.nodes[1].ping(Duration::ZERO, &alice);
        wire.settle(Duration::ZERO);
        assert_eq!(wire.sent - before, 4);
        assert_eq!(pongs(&wire.events[0]), 2);
        assert_eq!(pongs(&wire.events[1]), 2);
    }

    #[test]
    fn silent_peers_fail_and_leave_the_table() {
        // Mutation: drop every datagram from the start, so the opener never arrives.
        let mut wire = Wire::new(2);
        wire.drop = (0..10).collect();
        let bob = wire.enr(1);
        wire.nodes[0].add_enr(Duration::ZERO, bob.clone());
        let request_id = wire.nodes[0].ping(Duration::ZERO, &bob).expect("endpoint");
        wire.settle(Duration::ZERO);
        // Timing: nothing fails before 500 ms; at 500 ms the request lapses.
        wire.nodes[0].handle_timeout(Duration::from_millis(499));
        wire.drain(0);
        assert!(!wire.events[0].contains(&Event::RequestFailed {
            node: bob.node_id(),
            request_id,
        }));
        wire.nodes[0].handle_timeout(Duration::from_millis(500));
        wire.drain(0);
        assert!(wire.events[0].contains(&Event::RequestFailed {
            node: bob.node_id(),
            request_id,
        }));
        // Bob never answered, so he leaves the table at once.
        assert!(wire.nodes[0].table().get(&bob.node_id()).is_none());
    }

    #[test]
    fn repeated_packets_get_the_same_challenge() {
        // Mutation: drop alice's handshake, the third datagram, so bob's challenge stays open.
        let mut wire = Wire::new(2);
        wire.drop = vec![2];
        let bob = wire.enr(1);
        wire.nodes[0].ping(Duration::ZERO, &bob);
        wire.settle(Duration::ZERO);
        let first_challenge = wire.log[1].clone();

        // At 600 ms alice pings under her session; bob, still waiting, resends the same challenge.
        wire.nodes[0].ping(Duration::from_millis(600), &bob);
        wire.settle(Duration::from_millis(600));
        assert_eq!(wire.log.len(), 5);
        assert_eq!(wire.log[4], first_challenge);

        // The challenge names a packet alice no longer awaits, so her ping lapses at 1100 ms.
        wire.nodes[0].handle_timeout(Duration::from_millis(1100));
        wire.settle(Duration::from_millis(1100));
        let failures = wire.events[0]
            .iter()
            .filter(|event| matches!(event, Event::RequestFailed { .. }))
            .count();
        assert_eq!(failures, 2);

        // Bob's challenge lapsed at 1 s, so the next ping meets a fresh one and succeeds.
        wire.nodes[0].ping(Duration::from_millis(1200), &bob);
        wire.settle(Duration::from_millis(1200));
        assert_ne!(wire.log[6], first_challenge);
        assert!(
            wire.events[0]
                .iter()
                .any(|event| matches!(event, Event::Pong { .. }))
        );
    }

    #[test]
    fn find_node_answers_split_across_messages() {
        // Fixture state: bob's table holds 16 verified nodes at distance 256 from him.
        let mut wire = Wire::new(2);
        let bob_id = wire.enr(1).node_id();
        let config = TableConfig {
            ip_limits: None,
            ..TableConfig::default()
        };
        wire.nodes[1].table = RoutingTable::new(bob_id, config);
        let mut far = Vec::new();
        for seed in 10..=250_u8 {
            let enr = record(seed, 1);
            if bob_id.log_distance(&enr.node_id()) == LogDistance::MAX && far.len() < 16 {
                wire.nodes[1].table.insert(enr.clone(), Duration::ZERO);
                wire.nodes[1].table.record_success(&enr.node_id());
                far.push(enr);
            }
        }
        assert_eq!(far.len(), 16);

        // Alice asks for distance 256 and gets all 16 back across two messages.
        let bob = wire.enr(1);
        wire.nodes[0].find_node(Duration::ZERO, &bob, vec![LogDistance::MAX]);
        wire.settle(Duration::ZERO);
        let found = wire.events[0]
            .iter()
            .find_map(|event| match event {
                Event::NodesFound { enrs, .. } => Some(enrs.clone()),
                _ => None,
            })
            .expect("answer arrived");
        assert_eq!(found.len(), 16);
        // Opener, WHOAREYOU, handshake, then two NODES packets, each within 1280 bytes.
        assert_eq!(wire.sent, 5);
    }

    #[test]
    fn newer_records_are_fetched_after_ping() {
        // Bob knows alice at sequence 1; alice moves to sequence 2.
        let mut wire = Wire::new(2);
        let alice_v1 = wire.enr(0);
        let alice_v2 = alice_v1
            .to_builder()
            .udp4(9000)
            .build(&key(1))
            .expect("fits");
        wire.nodes[1].add_enr(Duration::ZERO, alice_v1.clone());
        wire.nodes[0].set_local_enr(alice_v2).expect("same key");
        // Bob pings alice; her PONG announces sequence 2, so bob asks for her record.
        wire.nodes[1].ping(Duration::ZERO, &alice_v1);
        wire.settle(Duration::ZERO);
        let held = wire.nodes[1]
            .table()
            .get(&alice_v1.node_id())
            .map(|entry| entry.enr.seq());
        assert_eq!(held, Some(2));
    }

    #[test]
    fn talk_requests_reach_the_application() {
        // Alice sends TALKREQ "ask" under protocol "proto"; bob's application sees it.
        let mut wire = Wire::new(2);
        let bob = wire.enr(1);
        let request_id = wire.nodes[0]
            .talk_request(Duration::ZERO, &bob, b"proto".to_vec(), b"ask".to_vec())
            .expect("endpoint");
        wire.settle(Duration::ZERO);
        let alice_addr = wire.enr(0).endpoints().udp_socket().expect("endpoint");
        assert!(wire.events[1].contains(&Event::TalkRequest {
            node: wire.enr(0).node_id(),
            addr: alice_addr,
            request_id,
            protocol: b"proto".to_vec(),
            request: b"ask".to_vec(),
        }));
        let alice_id = wire.enr(0).node_id();
        // Bob's application answers "ok", which reaches alice's application.
        wire.nodes[1].talk_response(alice_id, alice_addr, request_id, b"ok".to_vec());
        wire.settle(Duration::ZERO);
        assert!(wire.events[0].contains(&Event::TalkResponse {
            node: bob.node_id(),
            request_id,
            response: b"ok".to_vec(),
        }));
    }

    #[test]
    fn lookups_on_an_empty_table_finish_at_once() {
        // A lone node has nobody to ask, so the lookup reports no peers straight away.
        let mut wire = Wire::new(1);
        let id = wire.nodes[0].lookup(Duration::ZERO, NodeId([1; 32]), EnrFilter::Any, 16);
        wire.drain(0);
        assert_eq!(
            wire.events[0],
            [Event::LookupFinished {
                id,
                target: NodeId([1; 32]),
                peers: Vec::new(),
            }]
        );
    }

    #[test]
    fn garbage_is_ignored() {
        // Random bytes of every length up to 1300 never panic and never produce output.
        let mut wire = Wire::new(1);
        let mut rng = Csprng::from_seed([9; 32]);
        let from: SocketAddr = "10.9.9.9:1".parse().expect("address");
        for len in 0..1300 {
            let mut bytes = vec![0; len];
            rng.fill(&mut bytes);
            wire.nodes[0].handle_datagram(Duration::ZERO, from, &bytes);
        }
        assert_eq!(wire.nodes[0].poll_output(), None);
    }
}
