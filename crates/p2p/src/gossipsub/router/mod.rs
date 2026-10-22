//! The gossipsub router: a pure state machine over peers, topics, and time.
//!
//! # Overview
//!
//! The owner reports connections, feeds RPCs, and calls the heartbeat on a timer.
//! The router answers with RPCs to send and events for the application.
//! Time is a duration since an arbitrary origin, passed in by the caller.
//! Randomness comes from a seeded generator, so a simulation replays exactly.
//!
//! ```text
//!            add/remove peer, rpc, publish, validation, heartbeat(now)
//! owner ───────────────────────────────────────────────────────────▶ router
//! owner ◀─────────────────────────────── (peer, rpc) to send, events ──┘
//! ```
//!
//! A received message is not forwarded until the application validates it.
//! Accepted messages go to the mesh, rejected ones penalize their senders.

mod heartbeat;
mod inbound;

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt,
    net::IpAddr,
    time::Duration,
};

use super::{
    ControlMessage, GossipsubConfig, MessageId, ProtocolVersion, RawMessage, Rpc, SubOpts, Topic,
    ValidationOutcome,
    mcache::MessageCache,
    rpc::{Graft, PeerInfo, Prune},
    score::{PeerScore, PeerScoreParams, PeerScoreThresholds, RejectReason},
    seen::SeenCache,
};
use crate::{identity::PeerId, protobuf::ProtoMessage, rng::Rng};

/// Something the application must hear about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipsubEvent {
    /// A new message awaits validation.
    ///
    /// The application must answer with a validation outcome for this identifier.
    Message {
        /// The peer that delivered it first.
        source: PeerId,
        /// Its identifier.
        id: MessageId,
        /// The message.
        message: RawMessage,
    },
    /// A peer joined a topic.
    Subscribed {
        /// The peer.
        peer: PeerId,
        /// The topic.
        topic: Topic,
    },
    /// A peer left a topic.
    Unsubscribed {
        /// The peer.
        peer: PeerId,
        /// The topic.
        topic: Topic,
    },
    /// A well-scored peer pruned this node and suggested replacements.
    PeerExchange {
        /// The topic.
        topic: Topic,
        /// Suggested peers.
        peers: Vec<PeerId>,
    },
}

/// Why a publish failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublishError {
    /// The same content was already published or received recently.
    Duplicate,
    /// No peer is eligible to receive the message.
    InsufficientPeers,
    /// The encoded message exceeds the transmit limit.
    MessageTooLarge,
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate => f.write_str("message already published"),
            Self::InsufficientPeers => f.write_str("no peer to publish to"),
            Self::MessageTooLarge => f.write_str("message exceeds the transmit limit"),
        }
    }
}

impl Error for PublishError {}

/// What the router knows about a connected peer.
#[derive(Clone, Debug)]
struct PeerState {
    /// The negotiated protocol revision.
    version: ProtocolVersion,
    /// Whether this node dialed the peer, which counts for the outbound quota.
    outbound: bool,
    /// Topics the peer subscribes to.
    topics: BTreeSet<Topic>,
    /// Messages the peer said it does not want, with the time each notice expires.
    dont_send: BTreeMap<MessageId, Duration>,
    /// IHAVE messages received this heartbeat.
    ihave_received: usize,
    /// Identifiers requested from the peer this heartbeat.
    iwant_asked: usize,
    /// IDONTWANT identifiers received this heartbeat.
    idontwant_received: usize,
}

/// A message waiting for the application's verdict.
#[derive(Clone, Debug)]
struct Pending {
    /// The message.
    message: RawMessage,
    /// The peer that delivered it first.
    source: PeerId,
    /// Every peer that delivered it, who need not get it back.
    seen_from: BTreeSet<PeerId>,
    /// When it arrived.
    received_at: Duration,
}

/// The scorer and the thresholds it is compared against.
#[derive(Clone, Debug)]
struct Scoring {
    /// Counters and score function.
    score: PeerScore,
    /// Restriction levels.
    thresholds: PeerScoreThresholds,
}

/// The gossipsub router state machine.
#[derive(Debug)]
pub struct Router {
    /// Parameters.
    config: GossipsubConfig,
    /// Peer scoring, when enabled.
    scoring: Option<Scoring>,
    /// Randomness for peer selection.
    rng: Rng,
    /// Connected peers.
    peers: BTreeMap<PeerId, PeerState>,
    /// Topics this node subscribes to.
    subscriptions: BTreeSet<Topic>,
    /// Mesh peers per subscribed topic.
    mesh: BTreeMap<Topic, BTreeSet<PeerId>>,
    /// Fanout peers per topic published to without subscribing.
    fanout: BTreeMap<Topic, BTreeSet<PeerId>>,
    /// Last publish time per fanout topic.
    fanout_last_published: BTreeMap<Topic, Duration>,
    /// Graft backoffs per topic and peer, with their expiry.
    backoffs: BTreeMap<(Topic, PeerId), Duration>,
    /// Recent full messages.
    mcache: MessageCache,
    /// Recent message identifiers.
    seen: SeenCache,
    /// Messages awaiting validation.
    pending: BTreeMap<MessageId, Pending>,
    /// IWANT promises: peers that must deliver a message by a deadline.
    promises: BTreeMap<MessageId, BTreeMap<PeerId, Duration>>,
    /// Messages to send, one per RPC.
    outbox: VecDeque<(PeerId, Rpc)>,
    /// Subscriptions and control to send, merged per peer.
    control: BTreeMap<PeerId, Rpc>,
    /// Events for the application.
    events: VecDeque<GossipsubEvent>,
    /// Heartbeats run so far.
    heartbeat_ticks: u64,
}

impl Router {
    /// A router with no peers.
    ///
    /// # Arguments
    ///
    /// - `config`: the parameters.
    /// - `scoring`: score parameters and thresholds, or nothing to disable scoring.
    /// - `seed`: the seed of peer selection; equal seeds replay equal choices.
    #[must_use]
    pub fn new(
        config: GossipsubConfig,
        scoring: Option<(PeerScoreParams, PeerScoreThresholds)>,
        seed: u64,
    ) -> Self {
        Self {
            mcache: MessageCache::new(config.history_length, config.history_gossip),
            seen: SeenCache::new(config.seen_ttl),
            config,
            scoring: scoring.map(|(params, thresholds)| Scoring {
                score: PeerScore::new(params),
                thresholds,
            }),
            rng: Rng::new(seed),
            peers: BTreeMap::new(),
            subscriptions: BTreeSet::new(),
            mesh: BTreeMap::new(),
            fanout: BTreeMap::new(),
            fanout_last_published: BTreeMap::new(),
            backoffs: BTreeMap::new(),
            pending: BTreeMap::new(),
            promises: BTreeMap::new(),
            outbox: VecDeque::new(),
            control: BTreeMap::new(),
            events: VecDeque::new(),
            heartbeat_ticks: 0,
        }
    }

    /// The parameters.
    #[must_use]
    pub const fn config(&self) -> &GossipsubConfig {
        &self.config
    }

    /// The next RPC to send, and its recipient.
    pub fn poll_transmit(&mut self) -> Option<(PeerId, Rpc)> {
        // Full messages first: they carry the latency-critical payloads.
        if let Some(next) = self.outbox.pop_front() {
            return Some(next);
        }
        self.control.pop_first()
    }

    /// The next event for the application.
    pub fn poll_event(&mut self) -> Option<GossipsubEvent> {
        self.events.pop_front()
    }

    /// Mesh peers of a topic.
    pub fn mesh_peers(&self, topic: &Topic) -> impl Iterator<Item = &PeerId> {
        self.mesh.get(topic).into_iter().flatten()
    }

    /// Connected peers subscribed to a topic.
    pub fn topic_peers<'a>(&'a self, topic: &'a Topic) -> impl Iterator<Item = &'a PeerId> {
        self.peers
            .iter()
            .filter(move |(_, state)| state.topics.contains(topic))
            .map(|(peer, _)| peer)
    }

    /// Whether this node subscribes to a topic.
    #[must_use]
    pub fn is_subscribed(&self, topic: &Topic) -> bool {
        self.subscriptions.contains(topic)
    }

    /// A peer's current score, zero when scoring is off.
    #[must_use]
    pub fn peer_score(&self, peer: &PeerId, now: Duration) -> f64 {
        self.scoring
            .as_ref()
            .map_or(0.0, |scoring| scoring.score.score(peer, now))
    }

    /// Registers a connected peer and tells it this node's subscriptions.
    pub fn add_peer(&mut self, peer: PeerId, version: ProtocolVersion, outbound: bool) {
        if self.peers.contains_key(&peer) {
            return;
        }
        self.peers.insert(
            peer.clone(),
            PeerState {
                version,
                outbound,
                topics: BTreeSet::new(),
                dont_send: BTreeMap::new(),
                ihave_received: 0,
                iwant_asked: 0,
                idontwant_received: 0,
            },
        );
        if let Some(scoring) = &mut self.scoring {
            scoring.score.add_peer(peer.clone());
        }
        // A new peer learns every topic this node is in.
        let subscriptions: Vec<SubOpts> = self
            .subscriptions
            .iter()
            .map(|topic| SubOpts {
                subscribe: true,
                topic: topic.clone(),
            })
            .collect();
        if !subscriptions.is_empty() {
            self.control_rpc(&peer).subscriptions.extend(subscriptions);
        }
    }

    /// Forgets a disconnected peer.
    pub fn remove_peer(&mut self, peer: &PeerId, now: Duration) {
        if self.peers.remove(peer).is_none() {
            return;
        }
        for members in self.mesh.values_mut().chain(self.fanout.values_mut()) {
            members.remove(peer);
        }
        for promised in self.promises.values_mut() {
            promised.remove(peer);
        }
        self.control.remove(peer);
        self.outbox.retain(|(recipient, _)| recipient != peer);
        if let Some(scoring) = &mut self.scoring {
            scoring.score.remove_peer(peer, now);
        }
    }

    /// Records a peer's IP address, for the colocation score term.
    pub fn set_peer_ip(&mut self, peer: &PeerId, ip: IpAddr) {
        if let Some(scoring) = &mut self.scoring {
            scoring.score.set_ip(peer, ip);
        }
    }

    /// Sets the application-specific score term of a peer.
    pub fn set_application_score(&mut self, peer: &PeerId, score: f64) {
        if let Some(scoring) = &mut self.scoring {
            scoring.score.set_application_score(peer, score);
        }
    }

    /// Joins a topic, returning whether this node was not already in it.
    pub fn subscribe(&mut self, topic: Topic, now: Duration) -> bool {
        if !self.subscriptions.insert(topic.clone()) {
            return false;
        }
        // Phase 1: announce the subscription to every peer.
        let peers: Vec<PeerId> = self.peers.keys().cloned().collect();
        for peer in &peers {
            self.control_rpc(peer).subscriptions.push(SubOpts {
                subscribe: true,
                topic: topic.clone(),
            });
        }
        // Phase 2: build the mesh, starting from the fanout peers already in use.
        let mut members: Vec<PeerId> = self
            .fanout
            .remove(&topic)
            .unwrap_or_default()
            .into_iter()
            .filter(|peer| self.peer_score(peer, now) >= 0.0 && !self.in_backoff(&topic, peer, now))
            .collect();
        self.fanout_last_published.remove(&topic);
        members.truncate(self.config.mesh_n);
        // Top up with random topic peers.
        if members.len() < self.config.mesh_n {
            let mut candidates = self.graft_candidates(&topic, &members, now);
            self.rng.shuffle(&mut candidates);
            members.extend(
                candidates
                    .into_iter()
                    .take(self.config.mesh_n - members.len()),
            );
        }
        self.mesh.insert(topic.clone(), BTreeSet::new());
        for peer in members {
            self.graft_peer(&topic, peer, now);
        }
        true
    }

    /// Leaves a topic, returning whether this node was in it.
    pub fn unsubscribe(&mut self, topic: &Topic, now: Duration) -> bool {
        if !self.subscriptions.remove(topic) {
            return false;
        }
        let peers: Vec<PeerId> = self.peers.keys().cloned().collect();
        for peer in &peers {
            self.control_rpc(peer).subscriptions.push(SubOpts {
                subscribe: false,
                topic: topic.clone(),
            });
        }
        // Mesh peers get a PRUNE with the shorter unsubscribe backoff.
        let members = self.mesh.remove(topic).unwrap_or_default();
        for peer in members {
            if let Some(scoring) = &mut self.scoring {
                scoring.score.prune(&peer, topic);
            }
            let prune = self.make_prune(&peer, topic, true, self.config.unsubscribe_backoff, now);
            self.control_entry(&peer).prune.push(prune);
        }
        true
    }

    /// Publishes a message this node authored.
    pub fn publish(
        &mut self,
        topic: Topic,
        data: Vec<u8>,
        now: Duration,
    ) -> Result<MessageId, PublishError> {
        let message = RawMessage::anonymous(topic.clone(), data);
        // The envelope must fit in one RPC frame.
        if message.encode().len() + 16 > self.config.max_transmit_size {
            return Err(PublishError::MessageTooLarge);
        }
        let id = (self.config.message_id)(&topic, &message.data);
        if self.seen.contains(&id) {
            return Err(PublishError::Duplicate);
        }
        let recipients = self.publish_recipients(&topic, now);
        if recipients.is_empty() {
            return Err(PublishError::InsufficientPeers);
        }
        self.seen.insert(id, now);
        self.mcache.put(id, message.clone());
        for peer in recipients {
            self.send_message(peer, message.clone());
        }
        Ok(id)
    }

    /// Applies the application's verdict on a message, returning whether it was pending.
    pub fn report_validation(
        &mut self,
        id: &MessageId,
        outcome: ValidationOutcome,
        now: Duration,
    ) -> bool {
        let Some(pending) = self.pending.remove(id) else {
            return false;
        };
        let topic = pending.message.topic.clone();
        match outcome {
            ValidationOutcome::Accept => {
                if let Some(scoring) = &mut self.scoring {
                    scoring
                        .score
                        .deliver_message(&pending.source, *id, &topic, now);
                }
                self.mcache.put(*id, pending.message.clone());
                self.forward(id, &pending.message, &pending.seen_from);
            }
            ValidationOutcome::Reject => {
                if let Some(scoring) = &mut self.scoring {
                    scoring.score.reject_message(
                        &pending.source,
                        Some(*id),
                        &topic,
                        RejectReason::Invalid,
                    );
                }
            }
            ValidationOutcome::Ignore => {
                if let Some(scoring) = &mut self.scoring {
                    scoring.score.reject_message(
                        &pending.source,
                        Some(*id),
                        &topic,
                        RejectReason::Ignored,
                    );
                }
            }
        }
        true
    }

    /// Chooses the peers an own message goes to.
    fn publish_recipients(&mut self, topic: &Topic, now: Duration) -> Vec<PeerId> {
        let publish_threshold = self.thresholds().publish_threshold;
        // Flood publishing: every topic peer above the publish threshold, for speed.
        if self.config.flood_publish {
            return self
                .topic_peers(topic)
                .filter(|peer| self.peer_score(peer, now) >= publish_threshold)
                .cloned()
                .collect();
        }
        // Otherwise the mesh, or a fanout set for topics this node is not in.
        if let Some(members) = self.mesh.get(topic) {
            return members.iter().cloned().collect();
        }
        self.fanout_last_published.insert(topic.clone(), now);
        if self.fanout.get(topic).is_none_or(BTreeSet::is_empty) {
            let mut candidates: Vec<PeerId> = self
                .topic_peers(topic)
                .filter(|peer| self.peer_score(peer, now) >= publish_threshold)
                .cloned()
                .collect();
            self.rng.shuffle(&mut candidates);
            candidates.truncate(self.config.mesh_n);
            self.fanout
                .insert(topic.clone(), candidates.into_iter().collect());
        }
        self.fanout
            .get(topic)
            .map(|members| members.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Sends a validated message to the mesh, skipping peers that have it or declined it.
    fn forward(&mut self, id: &MessageId, message: &RawMessage, seen_from: &BTreeSet<PeerId>) {
        let recipients: Vec<PeerId> = self
            .mesh_peers(&message.topic)
            .filter(|peer| !seen_from.contains(*peer))
            .filter(|peer| {
                self.peers
                    .get(*peer)
                    .is_some_and(|state| !state.dont_send.contains_key(id))
            })
            .cloned()
            .collect();
        for peer in recipients {
            self.send_message(peer, message.clone());
        }
    }

    /// Queues one full message for a peer.
    fn send_message(&mut self, peer: PeerId, message: RawMessage) {
        self.outbox.push_back((
            peer,
            Rpc {
                publish: vec![message],
                ..Rpc::default()
            },
        ));
    }

    /// The pending control RPC of a peer, created on first use.
    fn control_rpc(&mut self, peer: &PeerId) -> &mut Rpc {
        self.control.entry(peer.clone()).or_default()
    }

    /// The pending control message of a peer, created on first use.
    fn control_entry(&mut self, peer: &PeerId) -> &mut ControlMessage {
        self.control_rpc(peer)
            .control
            .get_or_insert_with(ControlMessage::default)
    }

    /// The thresholds in force; without scoring, nothing is ever restricted.
    fn thresholds(&self) -> PeerScoreThresholds {
        self.scoring.as_ref().map_or(
            PeerScoreThresholds {
                gossip_threshold: f64::NEG_INFINITY,
                publish_threshold: f64::NEG_INFINITY,
                graylist_threshold: f64::NEG_INFINITY,
                accept_px_threshold: 0.0,
                opportunistic_graft_threshold: f64::NEG_INFINITY,
            },
            |scoring| scoring.thresholds,
        )
    }

    /// Whether this node dialed a peer.
    fn is_outbound(&self, peer: &PeerId) -> bool {
        self.peers.get(peer).is_some_and(|state| state.outbound)
    }

    /// Whether a peer may not be grafted to a topic yet.
    fn in_backoff(&self, topic: &Topic, peer: &PeerId, now: Duration) -> bool {
        self.backoffs
            .get(&(topic.clone(), peer.clone()))
            .is_some_and(|&expiry| expiry > now)
    }

    /// Topic peers eligible for the mesh: not in it, not backing off, and not negative.
    fn graft_candidates(&self, topic: &Topic, exclude: &[PeerId], now: Duration) -> Vec<PeerId> {
        let members = self.mesh.get(topic);
        self.topic_peers(topic)
            .filter(|peer| !exclude.contains(peer))
            .filter(|peer| members.is_none_or(|members| !members.contains(*peer)))
            .filter(|peer| !self.in_backoff(topic, peer, now))
            .filter(|peer| self.peer_score(peer, now) >= 0.0)
            .cloned()
            .collect()
    }

    /// Adds a peer to a mesh and tells it so.
    fn graft_peer(&mut self, topic: &Topic, peer: PeerId, now: Duration) {
        if let Some(scoring) = &mut self.scoring {
            scoring.score.graft(&peer, topic, now);
        }
        self.control_entry(&peer).graft.push(Graft {
            topic: topic.clone(),
        });
        self.mesh.entry(topic.clone()).or_default().insert(peer);
    }

    /// Removes a peer from a mesh and tells it so, with or without peer exchange.
    fn prune_peer(&mut self, topic: &Topic, peer: &PeerId, px: bool, now: Duration) {
        if let Some(members) = self.mesh.get_mut(topic) {
            members.remove(peer);
        }
        if let Some(scoring) = &mut self.scoring {
            scoring.score.prune(peer, topic);
        }
        let prune = self.make_prune(peer, topic, px, self.config.prune_backoff, now);
        self.control_entry(peer).prune.push(prune);
    }

    /// Builds a PRUNE and starts the matching local backoff.
    fn make_prune(
        &mut self,
        peer: &PeerId,
        topic: &Topic,
        px: bool,
        backoff: Duration,
        now: Duration,
    ) -> Prune {
        // This side also waits out the backoff before regrafting the peer.
        self.backoffs
            .insert((topic.clone(), peer.clone()), now + backoff);
        let version = self
            .peers
            .get(peer)
            .map_or(ProtocolVersion::V1_0, |state| state.version);
        // v1.0 peers understand neither backoff nor peer exchange.
        if !version.supports_px() {
            return Prune {
                topic: topic.clone(),
                peers: Vec::new(),
                backoff: None,
            };
        }
        let mut peers = Vec::new();
        if px {
            let mut candidates: Vec<PeerId> = self
                .topic_peers(topic)
                .filter(|candidate| *candidate != peer && self.peer_score(candidate, now) >= 0.0)
                .cloned()
                .collect();
            self.rng.shuffle(&mut candidates);
            candidates.truncate(self.config.prune_peers);
            peers = candidates
                .into_iter()
                .map(|id| PeerInfo {
                    peer_id: Some(id),
                    signed_peer_record: None,
                })
                .collect();
        }
        Prune {
            topic: topic.clone(),
            peers,
            backoff: Some(backoff.as_secs()),
        }
    }
}

#[cfg(test)]
mod tests;
