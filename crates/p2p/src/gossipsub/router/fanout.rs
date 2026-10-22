//! Fanout sets: the peers own messages go to, per topic this node publishes to but is not in.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use super::{context::Context, gossip::Gossip};
use crate::{gossipsub::Topic, identity::PeerId};

/// Fanout peers per topic, and when each set was last published to.
#[derive(Clone, Debug, Default)]
pub(super) struct Fanout {
    /// Members per topic.
    members: BTreeMap<Topic, BTreeSet<PeerId>>,
    /// Last publish time per topic.
    last_published: BTreeMap<Topic, Duration>,
}

impl Fanout {
    /// Removes the set of a topic this node joins, handing its members to the new mesh.
    pub(super) fn take(&mut self, topic: &Topic) -> BTreeSet<PeerId> {
        self.last_published.remove(topic);
        self.members.remove(topic).unwrap_or_default()
    }

    /// Drops a peer from the set of a topic.
    pub(super) fn remove_member(&mut self, topic: &Topic, peer: &PeerId) {
        if let Some(members) = self.members.get_mut(topic) {
            members.remove(peer);
        }
    }

    /// Drops a disconnected peer from every set.
    pub(super) fn remove_peer(&mut self, peer: &PeerId) {
        for members in self.members.values_mut() {
            members.remove(peer);
        }
    }

    /// The peers an own message on a topic goes to, picking a fresh set when none is live.
    pub(super) fn recipients(
        &mut self,
        topic: &Topic,
        cx: &mut Context,
        now: Duration,
    ) -> Vec<PeerId> {
        self.last_published.insert(topic.clone(), now);
        if self.members.get(topic).is_none_or(BTreeSet::is_empty) {
            let publish_threshold = cx.scorer.thresholds().publish_threshold;
            let mut candidates: Vec<PeerId> = cx
                .peers
                .topic_peers(topic)
                .filter(|peer| cx.scorer.score(peer, now) >= publish_threshold)
                .cloned()
                .collect();
            cx.rng.shuffle(&mut candidates);
            candidates.truncate(cx.config.mesh_n);
            self.members
                .insert(topic.clone(), candidates.into_iter().collect());
        }
        self.members
            .get(topic)
            .map(|members| members.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Expires idle sets, keeps the live ones at D peers, and gossips to them.
    pub(super) fn maintain(&mut self, gossip: &Gossip, cx: &mut Context, now: Duration) {
        let ttl = cx.config.fanout_ttl;
        // A set unused for the fanout lifetime is dropped.
        let expired: Vec<Topic> = self
            .last_published
            .iter()
            .filter(|(_, last)| **last + ttl < now)
            .map(|(topic, _)| topic.clone())
            .collect();
        for topic in expired {
            self.members.remove(&topic);
            self.last_published.remove(&topic);
        }
        let publish_threshold = cx.scorer.thresholds().publish_threshold;
        let topics: Vec<Topic> = self.members.keys().cloned().collect();
        for topic in &topics {
            // Peers that left the topic or fell below the publish threshold drop out.
            let mut members: Vec<PeerId> = self
                .members
                .get(topic)
                .into_iter()
                .flatten()
                .filter(|peer| {
                    cx.peers.subscribes(peer, topic)
                        && cx.scorer.score(peer, now) >= publish_threshold
                })
                .cloned()
                .collect();
            // Refill to D from the remaining topic peers.
            if members.len() < cx.config.mesh_n {
                let mut candidates: Vec<PeerId> = cx
                    .peers
                    .topic_peers(topic)
                    .filter(|peer| {
                        !members.contains(peer) && cx.scorer.score(peer, now) >= publish_threshold
                    })
                    .cloned()
                    .collect();
                cx.rng.shuffle(&mut candidates);
                let missing = cx.config.mesh_n - members.len();
                members.extend(candidates.into_iter().take(missing));
            }
            gossip.emit(topic, &members, cx, now);
            self.members
                .insert(topic.clone(), members.into_iter().collect());
        }
    }
}
