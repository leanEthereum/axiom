//! The meshes: the peers that get full messages, per subscribed topic.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use super::{GossipsubEvent, backoff::Backoffs, context::Context};
use crate::{
    gossipsub::{
        Topic,
        rpc::{Graft, PeerInfo, Prune},
    },
    identity::PeerId,
};

/// Mesh peers per subscribed topic, and the backoffs that keep pruned peers out.
#[derive(Clone, Debug, Default)]
pub(super) struct Mesh {
    /// Members per subscribed topic.
    members: BTreeMap<Topic, BTreeSet<PeerId>>,
    /// Graft backoffs per topic and peer.
    backoffs: Backoffs,
}

impl Mesh {
    /// Members of the mesh of a topic.
    pub(super) fn peers(&self, topic: &Topic) -> impl Iterator<Item = &PeerId> {
        self.members.get(topic).into_iter().flatten()
    }

    /// The members of a topic's mesh, when this node is in the topic.
    pub(super) fn members(&self, topic: &Topic) -> Option<&BTreeSet<PeerId>> {
        self.members.get(topic)
    }

    /// Whether this node has a mesh for a topic.
    pub(super) fn contains_topic(&self, topic: &Topic) -> bool {
        self.members.contains_key(topic)
    }

    /// Every topic with a mesh.
    pub(super) fn topics(&self) -> Vec<Topic> {
        self.members.keys().cloned().collect()
    }

    /// Whether a peer may not be grafted to a topic yet.
    pub(super) fn in_backoff(&self, topic: &Topic, peer: &PeerId, now: Duration) -> bool {
        self.backoffs.is_active(topic, peer, now)
    }

    /// Drops a peer from a mesh without telling it, returning whether it was a member.
    pub(super) fn remove_member(&mut self, topic: &Topic, peer: &PeerId) -> bool {
        self.members
            .get_mut(topic)
            .is_some_and(|members| members.remove(peer))
    }

    /// Drops a disconnected peer from every mesh.
    pub(super) fn remove_peer(&mut self, peer: &PeerId) {
        for members in self.members.values_mut() {
            members.remove(peer);
        }
    }

    /// Drops the backoffs that have run out.
    pub(super) fn expire_backoffs(&mut self, now: Duration) {
        self.backoffs.expire(now);
    }

    /// Builds the mesh of a newly joined topic, starting from its fanout peers.
    pub(super) fn join(
        &mut self,
        topic: &Topic,
        fanout: BTreeSet<PeerId>,
        cx: &mut Context,
        now: Duration,
    ) {
        // Fanout peers already in use come first, unless negative or backing off.
        let mut members: Vec<PeerId> = fanout
            .into_iter()
            .filter(|peer| cx.scorer.score(peer, now) >= 0.0 && !self.in_backoff(topic, peer, now))
            .collect();
        members.truncate(cx.config.mesh_n);
        // Top up with random topic peers.
        if members.len() < cx.config.mesh_n {
            let mut candidates = self.graft_candidates(topic, &members, cx, now);
            cx.rng.shuffle(&mut candidates);
            let missing = cx.config.mesh_n - members.len();
            members.extend(candidates.into_iter().take(missing));
        }
        self.members.insert(topic.clone(), BTreeSet::new());
        for peer in members {
            self.graft(topic, peer, cx, now);
        }
    }

    /// Leaves the mesh of a topic, sending every member a PRUNE with the unsubscribe backoff.
    pub(super) fn leave(&mut self, topic: &Topic, cx: &mut Context, now: Duration) {
        let members = self.members.remove(topic).unwrap_or_default();
        for peer in members {
            cx.scorer.prune(&peer, topic);
            let prune = self.make_prune(&peer, topic, true, cx.config.unsubscribe_backoff, cx, now);
            cx.outbox.control(&peer).prune.push(prune);
        }
    }

    /// Keeps one mesh between D_low and D_high, healthy and with enough outbound peers.
    pub(super) fn maintain(&mut self, topic: &Topic, ticks: u64, cx: &mut Context, now: Duration) {
        let config = cx.config;

        // Step 1: negative-score peers leave without peer exchange.
        let negative: Vec<PeerId> = self
            .peers(topic)
            .filter(|peer| cx.scorer.score(peer, now) < 0.0)
            .cloned()
            .collect();
        for peer in &negative {
            self.prune(topic, peer, false, cx, now);
        }

        // Step 2: with too few peers, graft random eligible ones up to D.
        //
        //     D_low = 6, mesh = 4, D = 8: graft 8 - 4 = 4
        let size = self.peers(topic).count();
        if size < config.mesh_n_low {
            let mut candidates = self.graft_candidates(topic, &[], cx, now);
            cx.rng.shuffle(&mut candidates);
            for peer in candidates.into_iter().take(config.mesh_n - size) {
                self.graft(topic, peer, cx, now);
            }
        }

        // Step 3: with too many peers, keep the best D_score, a random rest up to D, and D_out outbound.
        let size = self.peers(topic).count();
        if size > config.mesh_n_high {
            let keep = self.select_survivors(topic, cx, now);
            let excess: Vec<PeerId> = self
                .peers(topic)
                .filter(|peer| !keep.contains(peer))
                .cloned()
                .collect();
            for peer in &excess {
                self.prune(topic, peer, true, cx, now);
            }
        }

        // Step 4: a healthy mesh still needs D_out outbound peers against eclipse attacks.
        let size = self.peers(topic).count();
        let outbound = self
            .peers(topic)
            .filter(|peer| cx.peers.is_outbound(peer))
            .count();
        if size >= config.mesh_n_low && outbound < config.mesh_outbound_min {
            let mut candidates: Vec<PeerId> = self
                .graft_candidates(topic, &[], cx, now)
                .into_iter()
                .filter(|peer| cx.peers.is_outbound(peer))
                .collect();
            cx.rng.shuffle(&mut candidates);
            for peer in candidates
                .into_iter()
                .take(config.mesh_outbound_min - outbound)
            {
                self.graft(topic, peer, cx, now);
            }
        }

        // Step 5: opportunistic grafting lifts a mesh whose median score sagged.
        if cx.scorer.is_enabled() && ticks.is_multiple_of(config.opportunistic_graft_ticks) {
            self.opportunistic_graft(topic, cx, now);
        }
    }

    /// Accepts or refuses mesh join requests.
    pub(super) fn handle_graft(
        &mut self,
        from: &PeerId,
        grafts: Vec<Graft>,
        cx: &mut Context,
        now: Duration,
    ) {
        let score = cx.scorer.score(from, now);
        let outbound = cx.peers.is_outbound(from);
        for Graft { topic } in grafts {
            // Grafts for topics this node is not in are ignored, so the peer learns nothing.
            let Some(members) = self.members.get(&topic) else {
                continue;
            };
            if members.contains(from) {
                continue;
            }
            let mesh_size = members.len();
            // A graft during backoff is misbehaviour: penalize, refuse, restart the backoff.
            if let Some(expiry) = self.backoffs.expiry(&topic, from)
                && expiry > now
            {
                let mut penalty = 1;
                // Grafting right after being pruned is flooding: a second penalty.
                //
                //     pruned at t, backoff 60 s, flood threshold 10 s
                //
                // A graft before t + 10 s then costs 2.
                if now + cx.config.prune_backoff < expiry + cx.config.graft_flood_threshold {
                    penalty += 1;
                }
                cx.scorer.add_penalty(from, penalty);
                self.prune(&topic, from, false, cx, now);
                continue;
            }
            // Negative peers are refused without peer exchange.
            if score < 0.0 {
                self.prune(&topic, from, false, cx, now);
                continue;
            }
            // A full mesh refuses inbound peers but offers replacements.
            if mesh_size >= cx.config.mesh_n_high && !outbound {
                self.prune(&topic, from, true, cx, now);
                continue;
            }
            cx.scorer.graft(from, &topic, now);
            self.members.entry(topic).or_default().insert(from.clone());
        }
    }

    /// Applies mesh departures and backoffs, returning the peer exchange offers to report.
    pub(super) fn handle_prune(
        &mut self,
        from: &PeerId,
        prunes: Vec<Prune>,
        cx: &mut Context,
        now: Duration,
    ) -> Vec<GossipsubEvent> {
        let accept_px = cx.scorer.score(from, now) >= cx.scorer.thresholds().accept_px_threshold;
        let mut offers = Vec::new();
        for Prune {
            topic,
            peers,
            backoff,
        } in prunes
        {
            if self.remove_member(&topic, from) {
                cx.scorer.prune(from, &topic);
            }
            // Honour the announced backoff, or the default one.
            let backoff = backoff.map_or(cx.config.prune_backoff, Duration::from_secs);
            self.backoffs
                .extend(&topic, from, now.saturating_add(backoff));
            // Peer exchange only from peers trusted enough.
            let peers: Vec<PeerId> = peers.into_iter().filter_map(|info| info.peer_id).collect();
            if accept_px && !peers.is_empty() {
                offers.push(GossipsubEvent::PeerExchange { topic, peers });
            }
        }
        offers
    }

    /// Adds a peer to a mesh and tells it so.
    fn graft(&mut self, topic: &Topic, peer: PeerId, cx: &mut Context, now: Duration) {
        cx.scorer.graft(&peer, topic, now);
        cx.outbox.control(&peer).graft.push(Graft {
            topic: topic.clone(),
        });
        self.members.entry(topic.clone()).or_default().insert(peer);
    }

    /// Removes a peer from a mesh and tells it so, with or without peer exchange.
    fn prune(&mut self, topic: &Topic, peer: &PeerId, px: bool, cx: &mut Context, now: Duration) {
        if let Some(members) = self.members.get_mut(topic) {
            members.remove(peer);
        }
        cx.scorer.prune(peer, topic);
        let prune = self.make_prune(peer, topic, px, cx.config.prune_backoff, cx, now);
        cx.outbox.control(peer).prune.push(prune);
    }

    /// Builds a PRUNE and starts the matching local backoff.
    fn make_prune(
        &mut self,
        peer: &PeerId,
        topic: &Topic,
        px: bool,
        backoff: Duration,
        cx: &mut Context,
        now: Duration,
    ) -> Prune {
        // This side also waits out the backoff before regrafting the peer.
        self.backoffs.start(topic, peer, now + backoff);
        // v1.0 peers understand neither backoff nor peer exchange.
        if !cx.peers.version(peer).supports_px() {
            return Prune {
                topic: topic.clone(),
                peers: Vec::new(),
                backoff: None,
            };
        }
        let peers = if px {
            let mut candidates: Vec<PeerId> = cx
                .peers
                .topic_peers(topic)
                .filter(|candidate| *candidate != peer && cx.scorer.score(candidate, now) >= 0.0)
                .cloned()
                .collect();
            cx.rng.shuffle(&mut candidates);
            candidates.truncate(cx.config.prune_peers);
            candidates
                .into_iter()
                .map(|id| PeerInfo {
                    peer_id: Some(id),
                    signed_peer_record: None,
                })
                .collect()
        } else {
            Vec::new()
        };
        Prune {
            topic: topic.clone(),
            peers,
            backoff: Some(backoff.as_secs()),
        }
    }

    /// Topic peers eligible for the mesh: not in it, not backing off, and not negative.
    fn graft_candidates(
        &self,
        topic: &Topic,
        exclude: &[PeerId],
        cx: &Context,
        now: Duration,
    ) -> Vec<PeerId> {
        let members = self.members.get(topic);
        cx.peers
            .topic_peers(topic)
            .filter(|peer| !exclude.contains(peer))
            .filter(|peer| members.is_none_or(|members| !members.contains(*peer)))
            .filter(|peer| !self.in_backoff(topic, peer, now))
            .filter(|peer| cx.scorer.score(peer, now) >= 0.0)
            .cloned()
            .collect()
    }

    /// Picks the mesh members that survive an oversubscription prune.
    fn select_survivors(&self, topic: &Topic, cx: &mut Context, now: Duration) -> Vec<PeerId> {
        let config = cx.config;
        // Shuffle before the stable sort, so equal scores break ties at random.
        let mut members: Vec<PeerId> = self.peers(topic).cloned().collect();
        cx.rng.shuffle(&mut members);
        members.sort_by(|a, b| {
            cx.scorer
                .score(b, now)
                .partial_cmp(&cx.scorer.score(a, now))
                .unwrap_or(Ordering::Equal)
        });
        // The best D_score stay; the others compete at random for the remaining slots.
        let mut rest = members.split_off(config.mesh_n_score.min(members.len()));
        cx.rng.shuffle(&mut rest);
        let free = config.mesh_n.saturating_sub(members.len());
        let mut tail = rest.split_off(free.min(rest.len()));
        members.append(&mut rest);

        // Outbound quota: swap outbound peers from the tail for inbound ones among the random picks.
        //
        //     kept:  [score, score, score, score | in, in, out, in]   outbound 1 < D_out 2
        //     tail:  [in, out, in, in]
        //
        // The last random inbound pick makes room for the tail's outbound peer.
        let mut outbound = members
            .iter()
            .filter(|peer| cx.peers.is_outbound(peer))
            .count();
        let mut slot = members.len();
        while outbound < config.mesh_outbound_min {
            let Some(position) = tail.iter().position(|peer| cx.peers.is_outbound(peer)) else {
                break;
            };
            // Find the last inbound peer outside the score-protected prefix.
            let Some(victim) = (config.mesh_n_score..slot)
                .rev()
                .find(|&i| !cx.peers.is_outbound(&members[i]))
            else {
                break;
            };
            members[victim] = tail.swap_remove(position);
            slot = victim;
            outbound += 1;
        }
        members
    }

    /// Grafts peers scoring above the mesh median when the median is below the threshold.
    fn opportunistic_graft(&mut self, topic: &Topic, cx: &mut Context, now: Duration) {
        let threshold = cx.scorer.thresholds().opportunistic_graft_threshold;
        let mut scores: Vec<f64> = self
            .peers(topic)
            .map(|peer| cx.scorer.score(peer, now))
            .collect();
        if scores.len() < 2 {
            return;
        }
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        let median = scores[scores.len() / 2];
        if median >= threshold {
            return;
        }
        let mut candidates: Vec<PeerId> = self
            .graft_candidates(topic, &[], cx, now)
            .into_iter()
            .filter(|peer| cx.scorer.score(peer, now) > median)
            .collect();
        cx.rng.shuffle(&mut candidates);
        for peer in candidates
            .into_iter()
            .take(cx.config.opportunistic_graft_peers)
        {
            self.graft(topic, peer, cx, now);
        }
    }
}
