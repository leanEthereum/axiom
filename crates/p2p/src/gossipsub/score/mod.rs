//! Peer scoring, gossipsub v1.1: counters per peer and topic, and the score they give.

mod params;

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::IpAddr,
    time::Duration,
};

pub use params::{DecaySchedule, PeerScoreParams, PeerScoreThresholds, TopicScoreParams};

use super::{MessageId, Topic};
use crate::identity::PeerId;

/// Time a delivery record is kept, long enough to credit late duplicates.
const DELIVERY_RECORD_TTL: Duration = Duration::from_secs(120);

/// Counters of one peer in one topic.
#[derive(Clone, Copy, Debug, Default)]
struct TopicStats {
    /// Whether the peer is in this node's mesh for the topic.
    in_mesh: bool,
    /// When the peer joined the mesh.
    graft_time: Duration,
    /// P2: messages this peer delivered first.
    first_message_deliveries: f64,
    /// P3: messages this peer delivered while in the mesh.
    mesh_message_deliveries: f64,
    /// Whether the P3 activation period has passed.
    mesh_message_deliveries_active: bool,
    /// P3b: penalty carried from past prunes.
    mesh_failure_penalty: f64,
    /// P4: invalid messages from this peer.
    invalid_message_deliveries: f64,
}

impl TopicStats {
    /// Leaves the mesh, moving an active delivery deficit into the sticky failure penalty.
    ///
    /// The deficit then stops counting as P3, so it is charged once, as P3b.
    fn leave_mesh(&mut self, tp: &TopicScoreParams) {
        // Threshold: only an active member that under-delivered carries a deficit.
        let deficit = tp.mesh_message_deliveries_threshold - self.mesh_message_deliveries;
        if self.in_mesh && self.mesh_message_deliveries_active && deficit > 0.0 {
            self.mesh_failure_penalty = deficit.mul_add(deficit, self.mesh_failure_penalty);
        }
        self.in_mesh = false;
        self.mesh_message_deliveries_active = false;
    }
}

/// Counters of one peer.
#[derive(Clone, Debug, Default)]
struct PeerStats {
    /// Whether the peer is connected.
    connected: bool,
    /// When a disconnected peer's record is dropped.
    expires_at: Duration,
    /// Counters per topic.
    topics: BTreeMap<Topic, TopicStats>,
    /// The peer's address, for P6.
    ip: Option<IpAddr>,
    /// P7: accumulated behaviour penalties.
    behaviour_penalty: f64,
    /// P5: the application's opinion.
    application_score: f64,
}

/// What validation decided for a message.
#[derive(Clone, Copy, Debug, PartialEq)]
enum DeliveryStatus {
    /// Still being validated.
    Pending,
    /// Accepted at a time.
    Valid(Duration),
    /// Rejected.
    Invalid,
    /// Ignored, without penalty.
    Ignored,
}

/// Who delivered a message and what became of it.
#[derive(Clone, Debug)]
struct DeliveryRecord {
    /// Validation status.
    status: DeliveryStatus,
    /// Peers that delivered duplicates while it was pending.
    peers: BTreeSet<PeerId>,
}

/// Why a message was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// The message is invalid: its senders are penalized.
    Invalid,
    /// The message is unwanted but not malicious.
    Ignored,
}

/// The scoring state of every peer.
#[derive(Clone, Debug)]
pub struct PeerScore {
    /// The parameters.
    params: PeerScoreParams,
    /// Counters per peer, connected or retained.
    peers: BTreeMap<PeerId, PeerStats>,
    /// Peers per IP address, for P6.
    ips: BTreeMap<IpAddr, BTreeSet<PeerId>>,
    /// Delivery records per message.
    deliveries: BTreeMap<MessageId, DeliveryRecord>,
    /// Record creation times, oldest first, for expiry.
    delivery_queue: VecDeque<(Duration, MessageId)>,
    /// When the counters last decayed.
    last_decay: Duration,
}

impl PeerScore {
    /// A scorer with parameters and no peers.
    #[must_use]
    pub const fn new(params: PeerScoreParams) -> Self {
        Self {
            params,
            peers: BTreeMap::new(),
            ips: BTreeMap::new(),
            deliveries: BTreeMap::new(),
            delivery_queue: VecDeque::new(),
            last_decay: Duration::ZERO,
        }
    }

    /// The parameters.
    #[must_use]
    pub const fn params(&self) -> &PeerScoreParams {
        &self.params
    }

    /// The score of a peer at a time; unknown peers score zero.
    #[must_use]
    #[expect(
        clippy::suboptimal_flops,
        reason = "the sum reads term by term as the spec writes it"
    )]
    pub fn score(&self, peer: &PeerId, now: Duration) -> f64 {
        let Some(stats) = self.peers.get(peer) else {
            return 0.0;
        };
        let params = &self.params;

        // Phase 1: the topic contributions, P1 to P4, each scaled by its topic weight.
        let mut topic_score = 0.0;
        for (topic, topic_stats) in &stats.topics {
            let Some(tp) = params.topics.get(topic) else {
                continue;
            };
            let mut s = 0.0;
            // P1: whole quanta spent in the mesh, capped.
            if topic_stats.in_mesh {
                let quanta = now.saturating_sub(topic_stats.graft_time).as_secs_f64()
                    / tp.time_in_mesh_quantum.as_secs_f64();
                s += quanta.min(tp.time_in_mesh_cap) * tp.time_in_mesh_weight;
            }
            // P2: first deliveries, linear.
            s += topic_stats.first_message_deliveries * tp.first_message_deliveries_weight;
            // P3: squared deficit once active.
            //
            //     threshold 4, delivered 1 → deficit 3 → P3 = 9
            if topic_stats.mesh_message_deliveries_active
                && topic_stats.mesh_message_deliveries < tp.mesh_message_deliveries_threshold
            {
                let deficit =
                    tp.mesh_message_deliveries_threshold - topic_stats.mesh_message_deliveries;
                s += deficit * deficit * tp.mesh_message_deliveries_weight;
            }
            // P3b: the penalty carried from earlier prunes.
            s += topic_stats.mesh_failure_penalty * tp.mesh_failure_penalty_weight;
            // P4: squared invalid deliveries, so a few mistakes cost little and many cost a lot.
            s += topic_stats.invalid_message_deliveries
                * topic_stats.invalid_message_deliveries
                * tp.invalid_message_deliveries_weight;
            topic_score += s * tp.topic_weight;
        }
        // The cap bounds what good behaviour in topics can buy.
        if params.topic_score_cap > 0.0 && topic_score > params.topic_score_cap {
            topic_score = params.topic_score_cap;
        }

        // Phase 2: the peer-wide terms.
        let mut score = topic_score + stats.application_score * params.app_specific_weight;
        // P6: squared surplus of peers sharing this peer's address.
        if let Some(ip) = stats.ip {
            let sharing = self.ips.get(&ip).map_or(0, BTreeSet::len);
            let surplus = f64::from(u32::try_from(sharing).unwrap_or(u32::MAX))
                - params.ip_colocation_factor_threshold;
            if surplus > 0.0 {
                score += surplus * surplus * params.ip_colocation_factor_weight;
            }
        }
        // P7: squared surplus of behaviour penalties.
        let excess = stats.behaviour_penalty - params.behaviour_penalty_threshold;
        if excess > 0.0 {
            score += excess * excess * params.behaviour_penalty_weight;
        }
        score
    }

    /// Starts tracking a connected peer, reviving a retained record.
    pub fn add_peer(&mut self, peer: PeerId) {
        let stats = self.peers.entry(peer).or_default();
        stats.connected = true;
    }

    /// Stops tracking a disconnected peer, retaining a non-positive record.
    pub fn remove_peer(&mut self, peer: &PeerId, now: Duration) {
        // A positive record is dropped at once: forgetting good history helps nobody cheat.
        if self.score(peer, now) > 0.0 {
            self.forget(peer);
            return;
        }
        let Some(stats) = self.peers.get_mut(peer) else {
            return;
        };
        // Leaving the mesh counts as a prune, with its delivery penalty.
        for (topic, topic_stats) in &mut stats.topics {
            if let Some(tp) = self.params.topics.get(topic) {
                topic_stats.leave_mesh(tp);
            }
            topic_stats.first_message_deliveries = 0.0;
        }
        stats.connected = false;
        stats.expires_at = now + self.params.retain_score;
    }

    /// Records a peer's address for the colocation term.
    pub fn set_ip(&mut self, peer: &PeerId, ip: IpAddr) {
        let Some(stats) = self.peers.get_mut(peer) else {
            return;
        };
        // Move the peer from its old address group to the new one.
        if let Some(old) = stats.ip.replace(ip)
            && let Some(group) = self.ips.get_mut(&old)
        {
            group.remove(peer);
        }
        self.ips.entry(ip).or_default().insert(peer.clone());
    }

    /// Sets the application-specific term.
    pub fn set_application_score(&mut self, peer: &PeerId, score: f64) {
        if let Some(stats) = self.peers.get_mut(peer) {
            stats.application_score = score;
        }
    }

    /// Adds behaviour penalties, such as broken IWANT promises or grafts during backoff.
    pub fn add_penalty(&mut self, peer: &PeerId, count: usize) {
        if let Some(stats) = self.peers.get_mut(peer) {
            stats.behaviour_penalty += f64::from(u32::try_from(count).unwrap_or(u32::MAX));
        }
    }

    /// Notes that a peer joined the mesh of a topic.
    pub fn graft(&mut self, peer: &PeerId, topic: &Topic, now: Duration) {
        if let Some(topic_stats) = self.topic_stats(peer, topic) {
            topic_stats.in_mesh = true;
            topic_stats.graft_time = now;
            topic_stats.mesh_message_deliveries_active = false;
        }
    }

    /// Notes that a peer left the mesh of a topic.
    pub fn prune(&mut self, peer: &PeerId, topic: &Topic) {
        let Some(tp) = self.params.topics.get(topic).copied() else {
            return;
        };
        if let Some(topic_stats) = self.topic_stats(peer, topic) {
            topic_stats.leave_mesh(&tp);
        }
    }

    /// Opens a delivery record for a message seen for the first time.
    pub fn validate_message(&mut self, id: MessageId, now: Duration) {
        self.expire_deliveries(now);
        if self.deliveries.contains_key(&id) {
            return;
        }
        self.deliveries.insert(
            id,
            DeliveryRecord {
                status: DeliveryStatus::Pending,
                peers: BTreeSet::new(),
            },
        );
        self.delivery_queue.push_back((now, id));
    }

    /// Credits the first deliverer of an accepted message, and those that echoed it while pending.
    pub fn deliver_message(&mut self, from: &PeerId, id: MessageId, topic: &Topic, now: Duration) {
        self.mark_first_delivery(from, topic);
        let Some(record) = self.deliveries.get_mut(&id) else {
            return;
        };
        if record.status != DeliveryStatus::Pending {
            return;
        }
        record.status = DeliveryStatus::Valid(now);
        // Duplicates that arrived during validation were within any window.
        let echoes: Vec<PeerId> = record.peers.iter().cloned().collect();
        for peer in echoes {
            if peer != *from {
                self.mark_duplicate_delivery(&peer, topic, None, now);
            }
        }
    }

    /// Penalizes the deliverers of a rejected message, unless it was merely ignored.
    pub fn reject_message(
        &mut self,
        from: &PeerId,
        id: Option<MessageId>,
        topic: &Topic,
        reason: RejectReason,
    ) {
        let record = id.and_then(|id| self.deliveries.get_mut(&id));
        let Some(record) = record else {
            // No record: the message failed before validation, so only its sender is at fault.
            if reason == RejectReason::Invalid {
                self.mark_invalid(from, topic);
            }
            return;
        };
        if record.status != DeliveryStatus::Pending {
            return;
        }
        match reason {
            RejectReason::Ignored => record.status = DeliveryStatus::Ignored,
            RejectReason::Invalid => {
                record.status = DeliveryStatus::Invalid;
                // Everyone who forwarded the invalid message shares the blame.
                let peers: Vec<PeerId> = record.peers.iter().cloned().collect();
                self.mark_invalid(from, topic);
                for peer in peers {
                    self.mark_invalid(&peer, topic);
                }
            }
        }
    }

    /// Accounts a duplicate of a message already seen.
    pub fn duplicated_message(
        &mut self,
        from: &PeerId,
        id: MessageId,
        topic: &Topic,
        now: Duration,
    ) {
        let Some(record) = self.deliveries.get_mut(&id) else {
            return;
        };
        // Each peer counts once per message.
        if !record.peers.insert(from.clone()) {
            return;
        }
        match record.status {
            // Credited when validation finishes.
            DeliveryStatus::Pending | DeliveryStatus::Ignored => {}
            DeliveryStatus::Valid(validated) => {
                self.mark_duplicate_delivery(from, topic, Some(validated), now);
            }
            DeliveryStatus::Invalid => self.mark_invalid(from, topic),
        }
    }

    /// Decays every counter once per interval and drops expired records.
    pub fn refresh(&mut self, now: Duration) {
        if now.saturating_sub(self.last_decay) < self.params.decay_interval {
            return;
        }
        self.last_decay = now;
        let params = &self.params;
        let decay_to_zero = params.decay_to_zero;
        // Multiply a counter by its decay, snapping small values to zero.
        let decay = |value: &mut f64, factor: f64| {
            *value *= factor;
            if *value < decay_to_zero {
                *value = 0.0;
            }
        };
        let mut expired = Vec::new();
        for (peer, stats) in &mut self.peers {
            // Retained records of disconnected peers expire.
            if !stats.connected && stats.expires_at <= now {
                expired.push(peer.clone());
                continue;
            }
            for (topic, ts) in &mut stats.topics {
                let Some(tp) = params.topics.get(topic) else {
                    continue;
                };
                decay(
                    &mut ts.first_message_deliveries,
                    tp.first_message_deliveries_decay,
                );
                decay(
                    &mut ts.mesh_message_deliveries,
                    tp.mesh_message_deliveries_decay,
                );
                decay(&mut ts.mesh_failure_penalty, tp.mesh_failure_penalty_decay);
                decay(
                    &mut ts.invalid_message_deliveries,
                    tp.invalid_message_deliveries_decay,
                );
                // P3 activates once the peer has been in the mesh long enough.
                if ts.in_mesh
                    && now.saturating_sub(ts.graft_time) >= tp.mesh_message_deliveries_activation
                {
                    ts.mesh_message_deliveries_active = true;
                }
            }
            decay(&mut stats.behaviour_penalty, params.behaviour_penalty_decay);
        }
        for peer in expired {
            self.forget(&peer);
        }
        self.expire_deliveries(now);
    }

    /// Drops every trace of a peer.
    fn forget(&mut self, peer: &PeerId) {
        if let Some(stats) = self.peers.remove(peer)
            && let Some(ip) = stats.ip
            && let Some(group) = self.ips.get_mut(&ip)
        {
            group.remove(peer);
            if group.is_empty() {
                self.ips.remove(&ip);
            }
        }
    }

    /// The counters of a peer in a scored topic, created on first use.
    fn topic_stats(&mut self, peer: &PeerId, topic: &Topic) -> Option<&mut TopicStats> {
        // Unscored topics keep no counters.
        if !self.params.topics.contains_key(topic) {
            return None;
        }
        let stats = self.peers.get_mut(peer)?;
        Some(stats.topics.entry(topic.clone()).or_default())
    }

    /// Credits a first delivery, and a mesh delivery when the peer is in the mesh.
    fn mark_first_delivery(&mut self, peer: &PeerId, topic: &Topic) {
        let Some(tp) = self.params.topics.get(topic).copied() else {
            return;
        };
        if let Some(ts) = self.topic_stats(peer, topic) {
            ts.first_message_deliveries =
                (ts.first_message_deliveries + 1.0).min(tp.first_message_deliveries_cap);
            if ts.in_mesh {
                ts.mesh_message_deliveries =
                    (ts.mesh_message_deliveries + 1.0).min(tp.mesh_message_deliveries_cap);
            }
        }
    }

    /// Credits a mesh delivery for a duplicate that arrived within the window.
    fn mark_duplicate_delivery(
        &mut self,
        peer: &PeerId,
        topic: &Topic,
        validated: Option<Duration>,
        now: Duration,
    ) {
        let Some(tp) = self.params.topics.get(topic).copied() else {
            return;
        };
        // Timing: a duplicate long after validation shows the peer is slow, not helpful.
        if validated.is_some_and(|at| now.saturating_sub(at) > tp.mesh_message_deliveries_window) {
            return;
        }
        if let Some(ts) = self.topic_stats(peer, topic)
            && ts.in_mesh
        {
            ts.mesh_message_deliveries =
                (ts.mesh_message_deliveries + 1.0).min(tp.mesh_message_deliveries_cap);
        }
    }

    /// Counts an invalid delivery.
    fn mark_invalid(&mut self, peer: &PeerId, topic: &Topic) {
        if let Some(ts) = self.topic_stats(peer, topic) {
            ts.invalid_message_deliveries += 1.0;
        }
    }

    /// Drops delivery records past their lifetime.
    fn expire_deliveries(&mut self, now: Duration) {
        while let Some(&(at, id)) = self.delivery_queue.front() {
            if at + DELIVERY_RECORD_TTL > now {
                break;
            }
            self.delivery_queue.pop_front();
            self.deliveries.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PublicKey;

    /// A peer identifier from a seed byte.
    fn peer(seed: u8) -> PeerId {
        PeerId::from_public_key(&PublicKey::secp256k1([seed; 33]))
    }

    /// Hand-picked parameters with round numbers, one topic "t".
    fn params() -> PeerScoreParams {
        let topic = TopicScoreParams {
            topic_weight: 1.0,
            time_in_mesh_weight: 1.0,
            time_in_mesh_quantum: Duration::from_secs(1),
            time_in_mesh_cap: 10.0,
            first_message_deliveries_weight: 2.0,
            first_message_deliveries_decay: 0.5,
            first_message_deliveries_cap: 100.0,
            mesh_message_deliveries_weight: -1.0,
            mesh_message_deliveries_decay: 1.0,
            mesh_message_deliveries_cap: 100.0,
            mesh_message_deliveries_threshold: 4.0,
            mesh_message_deliveries_window: Duration::from_millis(10),
            mesh_message_deliveries_activation: Duration::from_secs(5),
            mesh_failure_penalty_weight: -1.0,
            mesh_failure_penalty_decay: 1.0,
            invalid_message_deliveries_weight: -10.0,
            invalid_message_deliveries_decay: 1.0,
        };
        PeerScoreParams {
            topics: BTreeMap::from([(Topic::new("t"), topic)]),
            topic_score_cap: 0.0,
            app_specific_weight: 1.0,
            ip_colocation_factor_weight: -5.0,
            ip_colocation_factor_threshold: 1.0,
            behaviour_penalty_weight: -1.0,
            behaviour_penalty_threshold: 2.0,
            behaviour_penalty_decay: 1.0,
            decay_interval: Duration::from_secs(1),
            decay_to_zero: 0.01,
            retain_score: Duration::from_secs(60),
        }
    }

    #[test]
    fn time_in_mesh_and_first_deliveries() {
        let mut score = PeerScore::new(params());
        let (a, t) = (peer(1), Topic::new("t"));
        score.add_peer(a.clone());
        // Grafted at t = 0; at t = 3 s, P1 = 3 quanta * weight 1 = 3.
        score.graft(&a, &t, Duration::ZERO);
        assert!((score.score(&a, Duration::from_secs(3)) - 3.0).abs() < 1e-9);
        // P1 caps at 10 quanta.
        assert!((score.score(&a, Duration::from_secs(50)) - 10.0).abs() < 1e-9);
        // One first delivery adds P2 = 1 * weight 2.
        let id = MessageId([1; 20]);
        score.validate_message(id, Duration::ZERO);
        score.deliver_message(&a, id, &t, Duration::ZERO);
        assert!((score.score(&a, Duration::from_secs(3)) - 5.0).abs() < 1e-9);
    }

    #[test]
    fn invalid_messages_are_squared() {
        let mut score = PeerScore::new(params());
        let (a, t) = (peer(1), Topic::new("t"));
        score.add_peer(a.clone());
        // Two invalid messages → P4 = 2^2 = 4 → 4 * -10 = -40.
        for byte in 0..2 {
            let id = MessageId([byte; 20]);
            score.validate_message(id, Duration::ZERO);
            score.reject_message(&a, Some(id), &t, RejectReason::Invalid);
        }
        assert!((score.score(&a, Duration::ZERO) + 40.0).abs() < 1e-9);
        // An ignored message costs nothing.
        let id = MessageId([9; 20]);
        score.validate_message(id, Duration::ZERO);
        score.reject_message(&a, Some(id), &t, RejectReason::Ignored);
        assert!((score.score(&a, Duration::ZERO) + 40.0).abs() < 1e-9);
    }

    #[test]
    fn echoes_of_an_invalid_message_share_the_blame() {
        let mut score = PeerScore::new(params());
        let (a, b, t) = (peer(1), peer(2), Topic::new("t"));
        score.add_peer(a.clone());
        score.add_peer(b.clone());
        let id = MessageId([1; 20]);
        // A delivers first, B echoes while it is pending, then it is rejected.
        score.validate_message(id, Duration::ZERO);
        score.duplicated_message(&b, id, &t, Duration::ZERO);
        score.reject_message(&a, Some(id), &t, RejectReason::Invalid);
        // Both get P4 = 1 → -10.
        assert!((score.score(&a, Duration::ZERO) + 10.0).abs() < 1e-9);
        assert!((score.score(&b, Duration::ZERO) + 10.0).abs() < 1e-9);
    }

    #[test]
    fn mesh_delivery_deficit_after_activation() {
        let mut score = PeerScore::new(params());
        let (a, t) = (peer(1), Topic::new("t"));
        score.add_peer(a.clone());
        score.graft(&a, &t, Duration::ZERO);
        // Before activation (5 s), no deficit applies: score = P1 only.
        score.refresh(Duration::from_secs(4));
        assert!((score.score(&a, Duration::from_secs(4)) - 4.0).abs() < 1e-9);
        // At 6 s the deficit is active: threshold 4, delivered 0 → 16 * -1.
        //
        //     P1 = 6, P3 = -16 → -10
        score.refresh(Duration::from_secs(6));
        assert!((score.score(&a, Duration::from_secs(6)) + 10.0).abs() < 1e-9);
        // A prune turns the deficit into a sticky P3b of 16.
        score.prune(&a, &t);
        assert!((score.score(&a, Duration::from_secs(6)) + 16.0).abs() < 1e-9);
    }

    #[test]
    fn ip_colocation_and_behaviour_penalty() {
        let mut score = PeerScore::new(params());
        let ip: IpAddr = [10, 0, 0, 1].into();
        // Three peers on one IP, threshold 1 → surplus 2 → 4 * -5 = -20 each.
        for seed in 1..=3 {
            score.add_peer(peer(seed));
            score.set_ip(&peer(seed), ip);
        }
        assert!((score.score(&peer(1), Duration::ZERO) + 20.0).abs() < 1e-9);
        // Five penalties, threshold 2 → excess 3 → 9 * -1 = -9 more.
        score.add_penalty(&peer(1), 5);
        assert!((score.score(&peer(1), Duration::ZERO) + 29.0).abs() < 1e-9);
    }

    #[test]
    fn decay_and_retention() {
        let mut score = PeerScore::new(params());
        let (a, t) = (peer(1), Topic::new("t"));
        score.add_peer(a.clone());
        // Four first deliveries → P2 = 4 * 2 = 8.
        for byte in 0..4 {
            let id = MessageId([byte; 20]);
            score.validate_message(id, Duration::ZERO);
            score.deliver_message(&a, id, &t, Duration::ZERO);
        }
        // One decay at factor 0.5 halves it: 2 deliveries → 4.
        score.refresh(Duration::from_secs(1));
        assert!((score.score(&a, Duration::from_secs(1)) - 4.0).abs() < 1e-9);
        // A positive peer is forgotten at once on disconnect.
        score.remove_peer(&a, Duration::from_secs(1));
        assert!(score.score(&a, Duration::from_secs(1)).abs() < f64::EPSILON);
    }

    #[test]
    fn negative_score_survives_reconnection() {
        let mut score = PeerScore::new(params());
        let a = peer(1);
        score.add_peer(a.clone());
        score.add_penalty(&a, 4);
        // Excess 2 → -4, retained across a reconnect within 60 s.
        score.remove_peer(&a, Duration::ZERO);
        score.add_peer(a.clone());
        assert!((score.score(&a, Duration::ZERO) + 4.0).abs() < 1e-9);
    }
}
