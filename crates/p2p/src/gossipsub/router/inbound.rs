//! Handling of RPCs received from peers.

use std::{collections::BTreeSet, time::Duration};

use super::{GossipsubEvent, Pending, Router};
use crate::{
    gossipsub::{
        ControlMessage, MessageId, RawMessage, Rpc, Topic,
        rpc::{Graft, IDontWant, IHave, IWant, Prune},
        score::RejectReason,
    },
    identity::PeerId,
};

impl Router {
    /// Processes one RPC from a connected peer.
    pub fn handle_rpc(&mut self, from: &PeerId, rpc: Rpc, now: Duration) {
        // Unknown peers have no stream with us; graylisted ones are ignored outright.
        if !self.peers.contains_key(from) {
            return;
        }
        if self.peer_score(from, now) < self.thresholds().graylist_threshold {
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
            self.handle_ihave(from, ihave, now);
            self.handle_iwant(from, &iwant, now);
            self.handle_graft(from, graft, now);
            self.handle_prune(from, prune, now);
            self.handle_idontwant(from, idontwant, now);
        }
    }

    /// Applies a peer joining or leaving a topic.
    fn handle_subscription(&mut self, from: &PeerId, topic: Topic, subscribe: bool) {
        let Some(state) = self.peers.get_mut(from) else {
            return;
        };
        if subscribe {
            if state.topics.insert(topic.clone()) {
                self.events.push_back(GossipsubEvent::Subscribed {
                    peer: from.clone(),
                    topic,
                });
            }
            return;
        }
        if !state.topics.remove(&topic) {
            return;
        }
        // A peer that left a topic can no longer be in its mesh or fanout.
        if self
            .mesh
            .get_mut(&topic)
            .is_some_and(|members| members.remove(from))
            && let Some(scoring) = &mut self.scoring
        {
            scoring.score.prune(from, &topic);
        }
        if let Some(members) = self.fanout.get_mut(&topic) {
            members.remove(from);
        }
        self.events.push_back(GossipsubEvent::Unsubscribed {
            peer: from.clone(),
            topic,
        });
    }

    /// Handles a full message: checks, deduplicates, and hands it to the application.
    fn handle_message(&mut self, from: &PeerId, message: RawMessage, now: Duration) {
        // StrictNoSign: authorship fields are a protocol violation, punished as invalid.
        if !message.is_strict_no_sign() {
            if let Some(scoring) = &mut self.scoring {
                scoring
                    .score
                    .reject_message(from, None, &message.topic, RejectReason::Invalid);
            }
            return;
        }
        // Messages on topics this node is not in are not relayed.
        if !self.subscriptions.contains(&message.topic) {
            return;
        }
        let id = (self.config.message_id)(&message.topic, &message.data);
        // Any delivery fulfils the IWANT promises made for this message.
        self.promises.remove(&id);

        // Phase 1: duplicates only feed the score.
        if !self.seen.insert(id, now) {
            if let Some(scoring) = &mut self.scoring {
                scoring
                    .score
                    .duplicated_message(from, id, &message.topic, now);
            }
            if let Some(pending) = self.pending.get_mut(&id) {
                pending.seen_from.insert(from.clone());
            }
            return;
        }
        if let Some(scoring) = &mut self.scoring {
            scoring.score.validate_message(id, now);
        }

        // Phase 2: large messages trigger IDONTWANT before validation, to stop duplicates early.
        //
        //     1 KiB threshold: a block (~100 KiB) qualifies, an attestation (~300 B) does not
        if message.data.len() >= self.config.idontwant_message_size_threshold {
            self.send_idontwant(from, &message.topic, id);
        }

        // Phase 3: hold the message until the application decides.
        let mut seen_from = BTreeSet::new();
        seen_from.insert(from.clone());
        self.pending.insert(
            id,
            Pending {
                message: message.clone(),
                source: from.clone(),
                seen_from,
                received_at: now,
            },
        );
        self.events.push_back(GossipsubEvent::Message {
            source: from.clone(),
            id,
            message,
        });
    }

    /// Tells v1.2 mesh peers not to send a message this node already has.
    fn send_idontwant(&mut self, from: &PeerId, topic: &Topic, id: MessageId) {
        let recipients: Vec<PeerId> = self
            .mesh_peers(topic)
            .filter(|peer| *peer != from)
            .filter(|peer| {
                self.peers
                    .get(*peer)
                    .is_some_and(|state| state.version.supports_idontwant())
            })
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
            self.outbox.push_back((
                peer,
                Rpc {
                    control: Some(control),
                    ..Rpc::default()
                },
            ));
        }
    }

    /// Answers gossip with IWANT for unseen messages, within per-peer budgets.
    fn handle_ihave(&mut self, from: &PeerId, ihaves: Vec<IHave>, now: Duration) {
        if ihaves.is_empty() || self.peer_score(from, now) < self.thresholds().gossip_threshold {
            return;
        }
        let max_messages = self.config.max_ihave_messages;
        let max_length = self.config.max_ihave_length;
        let Some(state) = self.peers.get_mut(from) else {
            return;
        };
        // Budget 1: IHAVE messages per heartbeat.
        state.ihave_received += 1;
        if state.ihave_received > max_messages || state.iwant_asked >= max_length {
            return;
        }
        // Budget 2: identifiers requested per heartbeat.
        let budget = max_length - state.iwant_asked;
        let mut wanted: Vec<MessageId> = ihaves
            .into_iter()
            .filter(|ihave| self.mesh.contains_key(&ihave.topic))
            .flat_map(|ihave| ihave.message_ids)
            .filter(|id| !self.seen.contains(id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if wanted.is_empty() {
            return;
        }
        // A random subset, so a peer cannot steer which messages are requested.
        self.rng.shuffle(&mut wanted);
        wanted.truncate(budget);
        if let Some(state) = self.peers.get_mut(from) {
            state.iwant_asked += wanted.len();
        }
        // Promise tracking: one random identifier must arrive within the follow-up time.
        let tracked = wanted[self.rng.below(wanted.len())];
        self.promises
            .entry(tracked)
            .or_default()
            .entry(from.clone())
            .or_insert(now + self.config.iwant_followup_time);
        self.control_entry(from).iwant.push(IWant {
            message_ids: wanted,
        });
    }

    /// Answers IWANT from the cache, limiting retransmissions per peer.
    fn handle_iwant(&mut self, from: &PeerId, iwants: &[IWant], now: Duration) {
        if iwants.is_empty() {
            return;
        }
        // Gossip is cut both ways below the gossip threshold.
        if self.peer_score(from, now) < self.thresholds().gossip_threshold {
            return;
        }
        let limit = self.config.gossip_retransmission;
        let ids: BTreeSet<MessageId> = iwants
            .iter()
            .flat_map(|iwant| iwant.message_ids.iter().copied())
            .collect();
        for id in ids {
            let Some((message, count)) = self.mcache.get_for_peer(&id, from) else {
                continue;
            };
            // A peer asking for the same message over and over is probing or attacking.
            if count > limit {
                continue;
            }
            let message = message.clone();
            self.send_message(from.clone(), message);
        }
    }

    /// Accepts or refuses mesh join requests.
    fn handle_graft(&mut self, from: &PeerId, grafts: Vec<Graft>, now: Duration) {
        let score = self.peer_score(from, now);
        let outbound = self.peers.get(from).is_some_and(|state| state.outbound);
        for Graft { topic } in grafts {
            // Grafts for topics this node is not in are ignored, so the peer learns nothing.
            let Some(members) = self.mesh.get(&topic) else {
                continue;
            };
            if members.contains(from) {
                continue;
            }
            let mesh_size = members.len();
            // A graft during backoff is misbehaviour: penalize, refuse, restart the backoff.
            if let Some(&expiry) = self.backoffs.get(&(topic.clone(), from.clone()))
                && expiry > now
            {
                let mut penalty = 1;
                // Grafting right after being pruned is flooding: a second penalty.
                //
                //     pruned at t, backoff 60 s, flood threshold 10 s
                //     → a graft before t + 10 s costs 2
                if now + self.config.prune_backoff < expiry + self.config.graft_flood_threshold {
                    penalty += 1;
                }
                if let Some(scoring) = &mut self.scoring {
                    scoring.score.add_penalty(from, penalty);
                }
                self.prune_peer(&topic, from, false, now);
                continue;
            }
            // Negative peers are refused without peer exchange.
            if score < 0.0 {
                self.prune_peer(&topic, from, false, now);
                continue;
            }
            // A full mesh refuses inbound peers but offers replacements.
            if mesh_size >= self.config.mesh_n_high && !outbound {
                self.prune_peer(&topic, from, true, now);
                continue;
            }
            if let Some(scoring) = &mut self.scoring {
                scoring.score.graft(from, &topic, now);
            }
            self.mesh.entry(topic).or_default().insert(from.clone());
        }
    }

    /// Applies mesh departures, backoffs, and peer exchange offers.
    fn handle_prune(&mut self, from: &PeerId, prunes: Vec<Prune>, now: Duration) {
        let accept_px = self.peer_score(from, now) >= self.thresholds().accept_px_threshold;
        for Prune {
            topic,
            peers,
            backoff,
        } in prunes
        {
            if self
                .mesh
                .get_mut(&topic)
                .is_some_and(|members| members.remove(from))
                && let Some(scoring) = &mut self.scoring
            {
                scoring.score.prune(from, &topic);
            }
            // Honour the announced backoff, or the default one.
            let backoff = backoff.map_or(self.config.prune_backoff, Duration::from_secs);
            let expiry = now.saturating_add(backoff);
            let entry = self
                .backoffs
                .entry((topic.clone(), from.clone()))
                .or_insert(expiry);
            *entry = (*entry).max(expiry);
            // Peer exchange only from peers trusted enough.
            let peers: Vec<PeerId> = peers.into_iter().filter_map(|info| info.peer_id).collect();
            if accept_px && !peers.is_empty() {
                self.events
                    .push_back(GossipsubEvent::PeerExchange { topic, peers });
            }
        }
    }

    /// Records messages a peer does not want, within a per-heartbeat budget.
    fn handle_idontwant(&mut self, from: &PeerId, idontwants: Vec<IDontWant>, now: Duration) {
        let max = self.config.max_idontwant_messages;
        let expiry = now + self.config.heartbeat_interval * self.config.idontwant_heartbeats;
        let Some(state) = self.peers.get_mut(from) else {
            return;
        };
        for id in idontwants
            .into_iter()
            .flat_map(|idontwant| idontwant.message_ids)
        {
            // Notices beyond the budget are ignored: honouring them only saves bandwidth.
            if state.idontwant_received >= max {
                return;
            }
            state.idontwant_received += 1;
            state.dont_send.insert(id, expiry);
        }
    }
}
