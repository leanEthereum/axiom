//! The gossipsub router: a pure state machine over peers, topics, and time.
//!
//! # Overview
//!
//! The owner reports connections, feeds RPCs, and calls the heartbeat on a timer.
//! The router answers with RPCs to send and events for the application.
//!
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
//!
//! The router composes parts that each own their tables, and delegates to them.
//!
//! ```text
//! router ─┬─ mesh          members per joined topic, graft backoffs
//!         ├─ fanout        recipients per topic published to but not joined
//!         ├─ gossip        message cache, IHAVE and IWANT, delivery promises
//!         ├─ validations   messages awaiting the application's verdict
//!         ├─ seen          recent identifiers, for deduplication
//!         └─ context       config, randomness, peers, scorer, outbox: shared by all parts
//! ```

mod backoff;
mod context;
mod fanout;
mod gossip;
mod mesh;
mod outbox;
mod peers;
mod promises;
mod scorer;
mod validation;

use std::{
    collections::{BTreeSet, VecDeque},
    net::IpAddr,
    time::Duration,
};

use thiserror::Error;

use self::{
    context::Context, fanout::Fanout, gossip::Gossip, mesh::Mesh, outbox::Outbox, peers::Peers,
    scorer::Scorer, validation::Validations,
};
use super::{
    ControlMessage, GossipsubConfig, MessageId, ProtocolVersion, RawMessage, Rpc, SubOpts, Topic,
    ValidationOutcome,
    rpc::IDontWant,
    score::{PeerScoreParams, PeerScoreThresholds, RejectReason},
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
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PublishError {
    /// The same content was already published or received recently.
    #[error("message {id:?} already published or seen")]
    Duplicate {
        /// Identifier of the message.
        id: MessageId,
    },
    /// No peer is eligible to receive the message.
    #[error("no peer to publish to on topic {topic}")]
    InsufficientPeers {
        /// The topic published on.
        topic: Topic,
    },
    /// The encoded message exceeds the transmit limit.
    #[error("message of {len} framed bytes exceeds the transmit limit of {max}")]
    MessageTooLarge {
        /// Encoded length plus the frame overhead allowance.
        len: usize,
        /// Largest frame the router transmits.
        max: usize,
    },
}

/// The gossipsub router state machine.
#[derive(Debug)]
pub struct Router {
    /// Parameters, randomness, peers, scores, and outbox, shared by every part.
    cx: Context,
    /// Topics this node subscribes to.
    subscriptions: BTreeSet<Topic>,
    /// Mesh peers per subscribed topic, with their graft backoffs.
    mesh: Mesh,
    /// Fanout peers per topic published to without subscribing.
    fanout: Fanout,
    /// The message cache and the IWANT promises.
    gossip: Gossip,
    /// Recent message identifiers.
    seen: SeenCache,
    /// Messages awaiting validation.
    validations: Validations,
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
            gossip: Gossip::new(config.history_length, config.history_gossip),
            seen: SeenCache::new(config.seen_ttl),
            cx: Context {
                config,
                rng: Rng::new(seed),
                peers: Peers::default(),
                scorer: Scorer::new(scoring),
                outbox: Outbox::default(),
            },
            subscriptions: BTreeSet::new(),
            mesh: Mesh::default(),
            fanout: Fanout::default(),
            validations: Validations::default(),
            events: VecDeque::new(),
            heartbeat_ticks: 0,
        }
    }

    /// The parameters.
    #[must_use]
    pub const fn config(&self) -> &GossipsubConfig {
        &self.cx.config
    }

    /// The next RPC to send, and its recipient.
    pub fn poll_transmit(&mut self) -> Option<(PeerId, Rpc)> {
        self.cx.outbox.poll()
    }

    /// The next event for the application.
    pub fn poll_event(&mut self) -> Option<GossipsubEvent> {
        self.events.pop_front()
    }

    /// Mesh peers of a topic.
    pub fn mesh_peers(&self, topic: &Topic) -> impl Iterator<Item = &PeerId> {
        self.mesh.peers(topic)
    }

    /// Connected peers subscribed to a topic.
    pub fn topic_peers<'a>(&'a self, topic: &'a Topic) -> impl Iterator<Item = &'a PeerId> {
        self.cx.peers.topic_peers(topic)
    }

    /// Whether this node subscribes to a topic.
    #[must_use]
    pub fn is_subscribed(&self, topic: &Topic) -> bool {
        self.subscriptions.contains(topic)
    }

    /// A peer's current score, zero when scoring is off.
    #[must_use]
    pub fn peer_score(&self, peer: &PeerId, now: Duration) -> f64 {
        self.cx.scorer.score(peer, now)
    }

    /// Registers a connected peer and tells it this node's subscriptions.
    pub fn add_peer(&mut self, peer: &PeerId, version: ProtocolVersion, outbound: bool) {
        if !self.cx.peers.insert(peer, version, outbound) {
            return;
        }
        self.cx.scorer.add_peer(peer.clone());
        // A new peer learns every topic this node is in.
        for topic in &self.subscriptions {
            self.cx.outbox.subscription(
                peer,
                SubOpts {
                    subscribe: true,
                    topic: topic.clone(),
                },
            );
        }
    }

    /// Updates the protocol revision of a peer, once its stream negotiation settles.
    pub fn set_peer_version(&mut self, peer: &PeerId, version: ProtocolVersion) {
        self.cx.peers.set_version(peer, version);
    }

    /// Forgets a disconnected peer.
    pub fn remove_peer(&mut self, peer: &PeerId, now: Duration) {
        if !self.cx.peers.remove(peer) {
            return;
        }
        self.mesh.remove_peer(peer);
        self.fanout.remove_peer(peer);
        self.gossip.promises.remove_peer(peer);
        self.cx.outbox.remove_peer(peer);
        self.cx.scorer.remove_peer(peer, now);
    }

    /// Records a peer's IP address, for the colocation score term.
    pub fn set_peer_ip(&mut self, peer: &PeerId, ip: IpAddr) {
        self.cx.scorer.set_ip(peer, ip);
    }

    /// Sets the application-specific score term of a peer.
    pub fn set_application_score(&mut self, peer: &PeerId, score: f64) {
        self.cx.scorer.set_application_score(peer, score);
    }

    /// Joins a topic, returning whether this node was not already in it.
    pub fn subscribe(&mut self, topic: &Topic, now: Duration) -> bool {
        if !self.subscriptions.insert(topic.clone()) {
            return false;
        }
        // Phase 1: announce the subscription to every peer.
        self.announce(topic, true);
        // Phase 2: build the mesh, starting from the fanout peers already in use.
        let fanout = self.fanout.take(topic);
        self.mesh.join(topic, fanout, &mut self.cx, now);
        true
    }

    /// Leaves a topic, returning whether this node was in it.
    pub fn unsubscribe(&mut self, topic: &Topic, now: Duration) -> bool {
        if !self.subscriptions.remove(topic) {
            return false;
        }
        self.announce(topic, false);
        // Mesh peers get a PRUNE with the shorter unsubscribe backoff.
        self.mesh.leave(topic, &mut self.cx, now);
        true
    }

    /// Publishes a message this node authored.
    pub fn publish(
        &mut self,
        topic: Topic,
        data: Vec<u8>,
        now: Duration,
    ) -> Result<MessageId, PublishError> {
        let message = RawMessage::anonymous(topic, data);
        // The envelope must fit in one RPC frame.
        let len = message.encode().len() + 16;
        if len > self.cx.config.max_transmit_size {
            return Err(PublishError::MessageTooLarge {
                len,
                max: self.cx.config.max_transmit_size,
            });
        }
        let id = (self.cx.config.message_id)(&message.topic, &message.data);
        if self.seen.contains(&id) {
            return Err(PublishError::Duplicate { id });
        }
        let recipients = self.publish_recipients(&message.topic, now);
        if recipients.is_empty() {
            return Err(PublishError::InsufficientPeers {
                topic: message.topic,
            });
        }
        self.seen.insert(id, now);
        self.gossip.put(id, message.clone());
        for peer in recipients {
            self.cx.outbox.send_message(peer, message.clone());
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
        let Some(pending) = self.validations.take(id) else {
            return false;
        };
        let topic = &pending.message.topic;
        match outcome {
            ValidationOutcome::Accept => {
                self.cx
                    .scorer
                    .deliver_message(&pending.source, *id, topic, now);
                self.gossip.put(*id, pending.message.clone());
                self.forward(id, &pending.message, &pending.seen_from);
            }
            ValidationOutcome::Reject => {
                self.cx.scorer.reject_message(
                    &pending.source,
                    Some(*id),
                    topic,
                    RejectReason::Invalid,
                );
            }
            ValidationOutcome::Ignore => {
                self.cx.scorer.reject_message(
                    &pending.source,
                    Some(*id),
                    topic,
                    RejectReason::Ignored,
                );
            }
        }
        true
    }

    /// Processes one RPC from a connected peer.
    pub fn handle_rpc(&mut self, from: &PeerId, rpc: Rpc, now: Duration) {
        // Unknown peers have no stream with us; graylisted ones are ignored outright.
        if !self.cx.peers.contains(from) {
            return;
        }
        if self.peer_score(from, now) < self.cx.scorer.thresholds().graylist_threshold {
            return;
        }
        // Phase 1: subscription changes come first, so later parts see the new topics.
        for subscription in rpc.subscriptions {
            self.handle_subscription(from, subscription.topic, subscription.subscribe);
        }
        // Phase 2: full messages.
        for message in rpc.publish {
            self.handle_message(from, message, now);
        }
        // Phase 3: control.
        if let Some(control) = rpc.control {
            let ControlMessage {
                ihave,
                iwant,
                graft,
                prune,
                idontwant,
            } = control;
            self.gossip
                .handle_ihave(from, ihave, &self.mesh, &self.seen, &mut self.cx, now);
            self.gossip.handle_iwant(from, &iwant, &mut self.cx, now);
            self.mesh.handle_graft(from, graft, &mut self.cx, now);
            let offers = self.mesh.handle_prune(from, prune, &mut self.cx, now);
            self.events.extend(offers);
            self.handle_idontwant(from, idontwant, now);
        }
    }

    /// Runs one heartbeat; the owner calls it every heartbeat interval.
    pub fn heartbeat(&mut self, now: Duration) {
        self.heartbeat_ticks += 1;

        // Phase 1: bookkeeping that the rest of the heartbeat relies on.
        self.expire_state(now);

        // Phase 2: repair every mesh, then gossip about it.
        for topic in &self.mesh.topics() {
            self.mesh
                .maintain(topic, self.heartbeat_ticks, &mut self.cx, now);
            let exclude: Vec<PeerId> = self.mesh.peers(topic).cloned().collect();
            self.gossip.emit(topic, &exclude, &mut self.cx, now);
        }

        // Phase 3: fanout sets expire, shed bad peers, and refill.
        self.fanout.maintain(&self.gossip, &mut self.cx, now);

        // Phase 4: slide the cache window.
        self.gossip.shift();
    }

    /// Queues a subscription change for every connected peer.
    fn announce(&mut self, topic: &Topic, subscribe: bool) {
        let peers: Vec<PeerId> = self.cx.peers.ids().cloned().collect();
        for peer in &peers {
            self.cx.outbox.subscription(
                peer,
                SubOpts {
                    subscribe,
                    topic: topic.clone(),
                },
            );
        }
    }

    /// Chooses the peers an own message goes to.
    fn publish_recipients(&mut self, topic: &Topic, now: Duration) -> Vec<PeerId> {
        let publish_threshold = self.cx.scorer.thresholds().publish_threshold;
        // Flood publishing: every topic peer above the publish threshold, for speed.
        if self.cx.config.flood_publish {
            return self
                .topic_peers(topic)
                .filter(|peer| self.peer_score(peer, now) >= publish_threshold)
                .cloned()
                .collect();
        }
        // Otherwise the mesh, or a fanout set for topics this node is not in.
        if let Some(members) = self.mesh.members(topic) {
            return members.iter().cloned().collect();
        }
        self.fanout.recipients(topic, &mut self.cx, now)
    }

    /// Sends a validated message to the mesh, skipping peers that have it or declined it.
    fn forward(&mut self, id: &MessageId, message: &RawMessage, seen_from: &BTreeSet<PeerId>) {
        let recipients: Vec<PeerId> = self
            .mesh
            .peers(&message.topic)
            .filter(|peer| !seen_from.contains(*peer))
            .filter(|peer| self.cx.peers.wants(peer, id))
            .cloned()
            .collect();
        for peer in recipients {
            self.cx.outbox.send_message(peer, message.clone());
        }
    }

    /// Applies a peer joining or leaving a topic.
    fn handle_subscription(&mut self, from: &PeerId, topic: Topic, subscribe: bool) {
        if !self.cx.peers.set_subscription(from, &topic, subscribe) {
            return;
        }
        if subscribe {
            self.events.push_back(GossipsubEvent::Subscribed {
                peer: from.clone(),
                topic,
            });
            return;
        }
        // A peer that left a topic can no longer be in its mesh or fanout.
        if self.mesh.remove_member(&topic, from) {
            self.cx.scorer.prune(from, &topic);
        }
        self.fanout.remove_member(&topic, from);
        self.events.push_back(GossipsubEvent::Unsubscribed {
            peer: from.clone(),
            topic,
        });
    }

    /// Handles a full message: checks, deduplicates, and hands it to the application.
    fn handle_message(&mut self, from: &PeerId, message: RawMessage, now: Duration) {
        // StrictNoSign: authorship fields are a protocol violation, punished as invalid.
        if !message.is_strict_no_sign() {
            self.cx
                .scorer
                .reject_message(from, None, &message.topic, RejectReason::Invalid);
            return;
        }
        // Messages on topics this node is not in are not relayed.
        if !self.subscriptions.contains(&message.topic) {
            return;
        }
        let id = (self.cx.config.message_id)(&message.topic, &message.data);
        // Any delivery fulfils the IWANT promises made for this message.
        self.gossip.promises.fulfil(&id);

        // Phase 1: duplicates only feed the score.
        if !self.seen.insert(id, now) {
            self.cx
                .scorer
                .duplicated_message(from, id, &message.topic, now);
            self.validations.note_duplicate(&id, from);
            return;
        }
        self.cx.scorer.validate_message(id, now);

        // Phase 2: large messages trigger IDONTWANT before validation, to stop duplicates early.
        //
        //     1 KiB threshold: a block (~100 KiB) qualifies, an attestation (~300 B) does not
        if message.data.len() >= self.cx.config.idontwant_message_size_threshold {
            self.send_idontwant(from, &message.topic, id);
        }

        // Phase 3: hold the message until the application decides.
        self.validations.hold(id, message.clone(), from, now);
        self.events.push_back(GossipsubEvent::Message {
            source: from.clone(),
            id,
            message,
        });
    }

    /// Tells v1.2 mesh peers not to send a message this node already has.
    fn send_idontwant(&mut self, from: &PeerId, topic: &Topic, id: MessageId) {
        let recipients: Vec<PeerId> = self
            .mesh
            .peers(topic)
            .filter(|peer| *peer != from)
            .filter(|peer| self.cx.peers.version(peer).supports_idontwant())
            .cloned()
            .collect();
        for peer in recipients {
            // Sent at once, not batched, so it overtakes the duplicate in flight.
            let control = ControlMessage {
                idontwant: vec![IDontWant {
                    message_ids: vec![id],
                }],
                ..ControlMessage::default()
            };
            self.cx.outbox.send_now(
                peer,
                Rpc {
                    control: Some(control),
                    ..Rpc::default()
                },
            );
        }
    }

    /// Records messages a peer does not want, within a per-heartbeat budget.
    fn handle_idontwant(&mut self, from: &PeerId, idontwants: Vec<IDontWant>, now: Duration) {
        let config = &self.cx.config;
        let expiry = now + config.heartbeat_interval * config.idontwant_heartbeats;
        let max = config.max_idontwant_messages;
        let ids = idontwants
            .into_iter()
            .flat_map(|idontwant| idontwant.message_ids);
        self.cx.peers.record_idontwant(from, ids, max, expiry);
    }

    /// Expires backoffs, promises, notices, and validations; resets per-heartbeat budgets.
    fn expire_state(&mut self, now: Duration) {
        self.cx.scorer.refresh(now);
        self.seen.expire(now);
        self.mesh.expire_backoffs(now);
        self.cx.peers.begin_heartbeat(now);

        // Broken promises: a peer announced a message, was asked, and never delivered.
        for peer in &self.gossip.promises.expire(now) {
            self.cx.scorer.add_penalty(peer, 1);
        }

        // Validations the application never answered are dropped as ignored.
        let stale = self
            .validations
            .stale(now, self.cx.config.validation_timeout);
        for id in stale {
            self.report_validation(&id, ValidationOutcome::Ignore, now);
        }
    }
}

#[cfg(test)]
mod tests;
