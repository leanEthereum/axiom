//! The heartbeat: periodic mesh repair, gossip emission, and bookkeeping.

use std::{cmp::Ordering, time::Duration};

use super::Router;
use crate::{
    gossipsub::{Topic, ValidationOutcome, rpc::IHave},
    identity::PeerId,
};

impl Router {
    /// Runs one heartbeat; the owner calls it every heartbeat interval.
    pub fn heartbeat(&mut self, now: Duration) {
        self.heartbeat_ticks += 1;

        // Phase 1: bookkeeping that the rest of the heartbeat relies on.
        self.expire_state(now);

        // Phase 2: repair every mesh, then gossip about it.
        let topics: Vec<Topic> = self.mesh.keys().cloned().collect();
        for topic in &topics {
            self.maintain_mesh(topic, now);
            let exclude: Vec<PeerId> = self.mesh_peers(topic).cloned().collect();
            self.emit_gossip(topic, &exclude, now);
        }

        // Phase 3: fanout sets expire, shed bad peers, and refill.
        self.maintain_fanout(now);

        // Phase 4: slide the cache window.
        self.mcache.shift();
    }

    /// Expires backoffs, promises, notices, and validations; resets per-heartbeat budgets.
    fn expire_state(&mut self, now: Duration) {
        if let Some(scoring) = &mut self.scoring {
            scoring.score.refresh(now);
        }
        self.seen.expire(now);
        self.backoffs.retain(|_, expiry| *expiry > now);
        for state in self.peers.values_mut() {
            state.ihave_received = 0;
            state.iwant_asked = 0;
            state.idontwant_received = 0;
            state.dont_send.retain(|_, expiry| *expiry > now);
        }

        // Broken promises: a peer announced a message, was asked, and never delivered.
        let mut broken: Vec<PeerId> = Vec::new();
        self.promises.retain(|_, promised| {
            promised.retain(|peer, deadline| {
                if *deadline <= now {
                    broken.push(peer.clone());
                    return false;
                }
                true
            });
            !promised.is_empty()
        });
        if let Some(scoring) = &mut self.scoring {
            for peer in &broken {
                scoring.score.add_penalty(peer, 1);
            }
        }

        // Validations the application never answered are dropped as ignored.
        let timeout = self.config.validation_timeout;
        let stale: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| now.saturating_sub(pending.received_at) >= timeout)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.report_validation(&id, ValidationOutcome::Ignore, now);
        }
    }

    /// Keeps one mesh between D_low and D_high, healthy and with enough outbound peers.
    fn maintain_mesh(&mut self, topic: &Topic, now: Duration) {
        let config = self.config;

        // Step 1: negative-score peers leave without peer exchange.
        let negative: Vec<PeerId> = self
            .mesh_peers(topic)
            .filter(|peer| self.peer_score(peer, now) < 0.0)
            .cloned()
            .collect();
        for peer in &negative {
            self.prune_peer(topic, peer, false, now);
        }

        // Step 2: too few peers → graft random eligible ones up to D.
        //
        //     D_low = 6, mesh = 4 → graft 8 - 4 = 4
        let size = self.mesh_peers(topic).count();
        if size < config.mesh_n_low {
            let mut candidates = self.graft_candidates(topic, &[], now);
            self.rng.shuffle(&mut candidates);
            for peer in candidates.into_iter().take(config.mesh_n - size) {
                self.graft_peer(topic, peer, now);
            }
        }

        // Step 3: too many peers → keep the best D_score, a random rest up to D, and D_out outbound.
        let size = self.mesh_peers(topic).count();
        if size > config.mesh_n_high {
            let keep = self.select_survivors(topic, now);
            let excess: Vec<PeerId> = self
                .mesh_peers(topic)
                .filter(|peer| !keep.contains(peer))
                .cloned()
                .collect();
            for peer in &excess {
                self.prune_peer(topic, peer, true, now);
            }
        }

        // Step 4: a healthy mesh still needs D_out outbound peers against eclipse attacks.
        let size = self.mesh_peers(topic).count();
        let outbound = self
            .mesh_peers(topic)
            .filter(|peer| self.is_outbound(peer))
            .count();
        if size >= config.mesh_n_low && outbound < config.mesh_outbound_min {
            let mut candidates: Vec<PeerId> = self
                .graft_candidates(topic, &[], now)
                .into_iter()
                .filter(|peer| self.is_outbound(peer))
                .collect();
            self.rng.shuffle(&mut candidates);
            for peer in candidates
                .into_iter()
                .take(config.mesh_outbound_min - outbound)
            {
                self.graft_peer(topic, peer, now);
            }
        }

        // Step 5: opportunistic grafting lifts a mesh whose median score sagged.
        if self.scoring.is_some() && self.heartbeat_ticks % config.opportunistic_graft_ticks == 0 {
            self.opportunistic_graft(topic, now);
        }
    }

    /// Picks the mesh members that survive an oversubscription prune.
    fn select_survivors(&mut self, topic: &Topic, now: Duration) -> Vec<PeerId> {
        let config = self.config;
        // Shuffle before the stable sort, so equal scores break ties at random.
        let mut members: Vec<PeerId> = self.mesh_peers(topic).cloned().collect();
        self.rng.shuffle(&mut members);
        members.sort_by(|a, b| {
            self.peer_score(b, now)
                .partial_cmp(&self.peer_score(a, now))
                .unwrap_or(Ordering::Equal)
        });
        // The best D_score stay; the others compete at random for the remaining slots.
        let mut rest = members.split_off(config.mesh_n_score.min(members.len()));
        self.rng.shuffle(&mut rest);
        let free = config.mesh_n.saturating_sub(members.len());
        let mut tail = rest.split_off(free.min(rest.len()));
        members.append(&mut rest);

        // Outbound quota: swap outbound peers from the tail for inbound ones among the random picks.
        //
        //     kept:  [score, score, score, score | in, in, out, in]   outbound 1 < D_out 2
        //     tail:  [in, out, in, in]
        //     → the last random inbound pick makes room for the tail's outbound peer
        let mut outbound = members.iter().filter(|peer| self.is_outbound(peer)).count();
        let mut slot = members.len();
        while outbound < config.mesh_outbound_min {
            let Some(position) = tail.iter().position(|peer| self.is_outbound(peer)) else {
                break;
            };
            // Find the last inbound peer outside the score-protected prefix.
            let Some(victim) = (config.mesh_n_score..slot)
                .rev()
                .find(|&i| !self.is_outbound(&members[i]))
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
    fn opportunistic_graft(&mut self, topic: &Topic, now: Duration) {
        let threshold = self.thresholds().opportunistic_graft_threshold;
        let mut scores: Vec<f64> = self
            .mesh_peers(topic)
            .map(|peer| self.peer_score(peer, now))
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
            .graft_candidates(topic, &[], now)
            .into_iter()
            .filter(|peer| self.peer_score(peer, now) > median)
            .collect();
        self.rng.shuffle(&mut candidates);
        for peer in candidates
            .into_iter()
            .take(self.config.opportunistic_graft_peers)
        {
            self.graft_peer(topic, peer, now);
        }
    }

    /// Expires idle fanout sets and keeps the live ones at D peers.
    fn maintain_fanout(&mut self, now: Duration) {
        let ttl = self.config.fanout_ttl;
        // A set unused for the fanout lifetime is dropped.
        let expired: Vec<Topic> = self
            .fanout_last_published
            .iter()
            .filter(|(_, last)| **last + ttl < now)
            .map(|(topic, _)| topic.clone())
            .collect();
        for topic in expired {
            self.fanout.remove(&topic);
            self.fanout_last_published.remove(&topic);
        }
        let publish_threshold = self.thresholds().publish_threshold;
        let topics: Vec<Topic> = self.fanout.keys().cloned().collect();
        for topic in &topics {
            // Peers that left the topic or fell below the publish threshold drop out.
            let keep: Vec<PeerId> = self
                .fanout
                .get(topic)
                .into_iter()
                .flatten()
                .filter(|peer| {
                    self.peers
                        .get(*peer)
                        .is_some_and(|state| state.topics.contains(topic))
                        && self.peer_score(peer, now) >= publish_threshold
                })
                .cloned()
                .collect();
            let mut members: Vec<PeerId> = keep;
            // Refill to D from the remaining topic peers.
            if members.len() < self.config.mesh_n {
                let mut candidates: Vec<PeerId> = self
                    .topic_peers(topic)
                    .filter(|peer| {
                        !members.contains(peer) && self.peer_score(peer, now) >= publish_threshold
                    })
                    .cloned()
                    .collect();
                self.rng.shuffle(&mut candidates);
                let missing = self.config.mesh_n - members.len();
                members.extend(candidates.into_iter().take(missing));
            }
            self.emit_gossip(topic, &members, now);
            self.fanout
                .insert(topic.clone(), members.into_iter().collect());
        }
    }

    /// Announces cached message identifiers to random non-mesh peers.
    fn emit_gossip(&mut self, topic: &Topic, exclude: &[PeerId], now: Duration) {
        let mut ids = self.mcache.gossip_ids(topic);
        if ids.is_empty() {
            return;
        }
        let gossip_threshold = self.thresholds().gossip_threshold;
        let mut candidates: Vec<PeerId> = self
            .topic_peers(topic)
            .filter(|peer| {
                !exclude.contains(peer) && self.peer_score(peer, now) >= gossip_threshold
            })
            .cloned()
            .collect();
        // Target max(D_lazy, gossip_factor * eligible) peers.
        //
        //     40 eligible, factor 0.25 → 10 > D_lazy 6 → gossip to 10
        let factor_target = (self.config.gossip_factor
            * f64::from(u32::try_from(candidates.len()).unwrap_or(u32::MAX)))
            as usize;
        let target = self.config.gossip_lazy.max(factor_target);
        self.rng.shuffle(&mut candidates);
        candidates.truncate(target);
        // A peer accepts at most max_ihave_length identifiers per heartbeat.
        if ids.len() > self.config.max_ihave_length {
            self.rng.shuffle(&mut ids);
            ids.truncate(self.config.max_ihave_length);
        }
        for peer in candidates {
            let ihave = IHave {
                topic: topic.clone(),
                message_ids: ids.clone(),
            };
            self.control_entry(&peer).ihave.push(ihave);
        }
    }
}
