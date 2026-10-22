//! Lazy pull: IHAVE announcements, IWANT requests, and the promises between them.

use std::{collections::BTreeSet, time::Duration};

use super::{context::Context, mesh::Mesh, promises::Promises};
use crate::{
    gossipsub::{
        MessageId, RawMessage, Topic,
        mcache::MessageCache,
        rpc::{IHave, IWant},
        seen::SeenCache,
    },
    identity::PeerId,
};

/// The message cache gossip draws on, and the IWANT promises it is owed.
#[derive(Clone, Debug)]
pub(super) struct Gossip {
    /// Recent full messages.
    cache: MessageCache,
    /// Peers that must deliver an announced message by a deadline.
    pub(super) promises: Promises,
}

impl Gossip {
    /// Gossip over a cache of a number of heartbeats, announcing the most recent few.
    pub(super) fn new(history_length: usize, history_gossip: usize) -> Self {
        Self {
            cache: MessageCache::new(history_length, history_gossip),
            promises: Promises::default(),
        }
    }

    /// Caches a message, so it can be announced and served.
    pub(super) fn put(&mut self, id: MessageId, message: RawMessage) {
        self.cache.put(id, message);
    }

    /// Slides the cache window by one heartbeat.
    pub(super) fn shift(&mut self) {
        self.cache.shift();
    }

    /// Announces cached message identifiers to random topic peers outside a set.
    pub(super) fn emit(&self, topic: &Topic, exclude: &[PeerId], cx: &mut Context, now: Duration) {
        let mut ids = self.cache.gossip_ids(topic);
        if ids.is_empty() {
            return;
        }
        let gossip_threshold = cx.scorer.thresholds().gossip_threshold;
        let mut candidates: Vec<PeerId> = cx
            .peers
            .topic_peers(topic)
            .filter(|peer| {
                !exclude.contains(peer) && cx.scorer.score(peer, now) >= gossip_threshold
            })
            .cloned()
            .collect();
        // Target max(D_lazy, gossip_factor * eligible) peers.
        //
        //     40 eligible, factor 0.25: 40 * 0.25 = 10 > D_lazy = 6, gossip to 10
        // Invariant: the factor lies in [0, 1], so the product is a non-negative count.
        let eligible = f64::from(u32::try_from(candidates.len()).unwrap_or(u32::MAX));
        #[expect(
            clippy::cast_sign_loss,
            reason = "the product is clamped to be non-negative"
        )]
        let factor_target = (cx.config.gossip_factor * eligible).max(0.0) as usize;
        let target = cx.config.gossip_lazy.max(factor_target);
        cx.rng.shuffle(&mut candidates);
        candidates.truncate(target);
        // A peer accepts at most max_ihave_length identifiers per heartbeat.
        if ids.len() > cx.config.max_ihave_length {
            cx.rng.shuffle(&mut ids);
            ids.truncate(cx.config.max_ihave_length);
        }
        for peer in candidates {
            let ihave = IHave {
                topic: topic.clone(),
                message_ids: ids.clone(),
            };
            cx.outbox.control(&peer).ihave.push(ihave);
        }
    }

    /// Answers gossip with IWANT for unseen messages, within per-peer budgets.
    pub(super) fn handle_ihave(
        &mut self,
        from: &PeerId,
        ihaves: Vec<IHave>,
        mesh: &Mesh,
        seen: &SeenCache,
        cx: &mut Context,
        now: Duration,
    ) {
        if ihaves.is_empty() || cx.scorer.score(from, now) < cx.scorer.thresholds().gossip_threshold
        {
            return;
        }
        let Some(budget) = cx.peers.iwant_budget(
            from,
            cx.config.max_ihave_messages,
            cx.config.max_ihave_length,
        ) else {
            return;
        };
        let mut wanted: Vec<MessageId> = ihaves
            .into_iter()
            .filter(|ihave| mesh.contains_topic(&ihave.topic))
            .flat_map(|ihave| ihave.message_ids)
            .filter(|id| !seen.contains(id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if wanted.is_empty() {
            return;
        }
        // A random subset, so a peer cannot steer which messages are requested.
        cx.rng.shuffle(&mut wanted);
        wanted.truncate(budget);
        cx.peers.record_iwant(from, wanted.len());
        // Promise tracking: one random identifier must arrive within the follow-up time.
        let tracked = wanted[cx.rng.below(wanted.len())];
        self.promises
            .track(tracked, from, now + cx.config.iwant_followup_time);
        cx.outbox.control(from).iwant.push(IWant {
            message_ids: wanted,
        });
    }

    /// Answers IWANT from the cache, limiting retransmissions per peer.
    pub(super) fn handle_iwant(
        &mut self,
        from: &PeerId,
        iwants: &[IWant],
        cx: &mut Context,
        now: Duration,
    ) {
        if iwants.is_empty() {
            return;
        }
        // Gossip is cut both ways below the gossip threshold.
        if cx.scorer.score(from, now) < cx.scorer.thresholds().gossip_threshold {
            return;
        }
        let limit = cx.config.gossip_retransmission;
        let ids: BTreeSet<MessageId> = iwants
            .iter()
            .flat_map(|iwant| iwant.message_ids.iter().copied())
            .collect();
        for id in ids {
            let Some((message, count)) = self.cache.get_for_peer(&id, from) else {
                continue;
            };
            // A peer asking for the same message over and over is probing or attacking.
            if count > limit {
                continue;
            }
            cx.outbox.send_message(from.clone(), message.clone());
        }
    }
}
