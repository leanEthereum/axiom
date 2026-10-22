//! Peer score parameters and thresholds, with an Ethereum parameterization.
//!
//! # Overview
//!
//! The score of a peer is a weighted sum of seven counters, P1 to P7.
//!
//! ```text
//! score = min(cap, sum_topic w_t * (w1 P1 + w2 P2 + w3 P3 + w3b P3b + w4 P4))
//!       + w5 P5 + w6 P6 + w7 P7
//!
//! P1   time in mesh, in quanta, capped              rewards stable mesh members
//! P2   first deliveries, decaying, capped           rewards useful forwarders
//! P3   squared deficit of mesh deliveries           punishes silent mesh members
//! P3b  squared deficit when pruned, decaying        remembers past silence
//! P4   squared invalid deliveries, decaying         punishes invalid messages
//! P5   application-specific score
//! P6   squared surplus of peers sharing an IP       punishes sybils
//! P7   squared surplus of behaviour penalties       punishes protocol abuse
//! ```
//!
//! Counters decay once per decay interval: c = c * decay, and zero below a floor.
//!
//! The consensus specs leave the values to clients.
//! The Ethereum parameterization follows the derivation lighthouse publishes.
//! See gossipsub v1.1, peer scoring.

use std::{collections::BTreeMap, time::Duration};

use crate::gossipsub::Topic;

/// The score of a perfect peer in one topic from P1, before the topic weight.
const MAX_IN_MESH_SCORE: f64 = 10.0;

/// The score of a perfect peer in one topic from P2, before the topic weight.
const MAX_FIRST_MESSAGE_DELIVERIES_SCORE: f64 = 40.0;

/// Parameters of one topic's contribution.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TopicScoreParams {
    /// Weight of the whole topic.
    pub topic_weight: f64,

    /// P1 weight, positive.
    pub time_in_mesh_weight: f64,
    /// P1 unit of time.
    pub time_in_mesh_quantum: Duration,
    /// P1 ceiling, in quanta.
    pub time_in_mesh_cap: f64,

    /// P2 weight, positive.
    pub first_message_deliveries_weight: f64,
    /// P2 decay factor per interval.
    pub first_message_deliveries_decay: f64,
    /// P2 ceiling.
    pub first_message_deliveries_cap: f64,

    /// P3 weight, negative; zero disables it.
    pub mesh_message_deliveries_weight: f64,
    /// P3 decay factor per interval.
    pub mesh_message_deliveries_decay: f64,
    /// P3 ceiling.
    pub mesh_message_deliveries_cap: f64,
    /// P3 deliveries expected; fewer give a squared deficit.
    pub mesh_message_deliveries_threshold: f64,
    /// Time after validation during which a duplicate still counts as a mesh delivery.
    pub mesh_message_deliveries_window: Duration,
    /// Time in mesh before P3 applies, so new members are not punished.
    pub mesh_message_deliveries_activation: Duration,

    /// P3b weight, negative.
    pub mesh_failure_penalty_weight: f64,
    /// P3b decay factor per interval.
    pub mesh_failure_penalty_decay: f64,

    /// P4 weight, negative.
    pub invalid_message_deliveries_weight: f64,
    /// P4 decay factor per interval.
    pub invalid_message_deliveries_decay: f64,
}

/// Parameters of the whole score function.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerScoreParams {
    /// Topic parameters; topics absent here do not contribute.
    pub topics: BTreeMap<Topic, TopicScoreParams>,
    /// Ceiling on the sum of topic contributions; zero means no ceiling.
    pub topic_score_cap: f64,
    /// P5 weight.
    pub app_specific_weight: f64,
    /// P6 weight, negative.
    pub ip_colocation_factor_weight: f64,
    /// P6 peers tolerated per IP before the surplus counts.
    pub ip_colocation_factor_threshold: f64,
    /// P7 weight, negative.
    pub behaviour_penalty_weight: f64,
    /// P7 penalties tolerated before the surplus counts.
    pub behaviour_penalty_threshold: f64,
    /// P7 decay factor per interval.
    pub behaviour_penalty_decay: f64,
    /// Time between counter decays.
    pub decay_interval: Duration,
    /// Counters below this snap to zero.
    pub decay_to_zero: f64,
    /// Time a disconnected peer's score is remembered, so reconnecting does not reset it.
    pub retain_score: Duration,
}

/// Score levels at which the router restricts a peer.
///
/// ```text
/// graylist < publish < gossip < 0 < opportunistic graft, accept px
///
/// score < gossip         no gossip to or from the peer
/// score < publish        own messages are not flood-published to the peer
/// score < graylist       every RPC from the peer is ignored
/// score >= accept px     peer exchange records from the peer are used
/// median < opp. graft    the heartbeat grafts better-scoring peers
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PeerScoreThresholds {
    /// Below this, gossip is cut.
    pub gossip_threshold: f64,
    /// Below this, flood publishing skips the peer.
    pub publish_threshold: f64,
    /// Below this, the peer is ignored entirely.
    pub graylist_threshold: f64,
    /// At or above this, peer exchange is accepted.
    pub accept_px_threshold: f64,
    /// Median mesh score below which opportunistic grafting runs.
    pub opportunistic_graft_threshold: f64,
}

impl PeerScoreThresholds {
    /// The thresholds Ethereum clients use.
    #[must_use]
    pub const fn ethereum() -> Self {
        Self {
            gossip_threshold: -4000.0,
            publish_threshold: -8000.0,
            graylist_threshold: -16000.0,
            accept_px_threshold: 100.0,
            opportunistic_graft_threshold: 5.0,
        }
    }
}

/// How score counters decay: by a factor once per interval, until a floor counts as zero.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DecaySchedule {
    /// Time between two decay steps.
    pub interval: Duration,
    /// The value below which a counter resets to zero.
    pub to_zero: f64,
}

impl DecaySchedule {
    /// The per-interval factor that shrinks a counter to the floor over a given time.
    ///
    /// ```text
    /// decay^(time / interval) = to_zero
    /// decay = to_zero^(interval / time)
    /// ```
    #[must_use]
    pub fn factor_over(self, time: Duration) -> f64 {
        let ticks = time.as_secs_f64() / self.interval.as_secs_f64();
        self.to_zero.powf(1.0 / ticks)
    }
}

impl PeerScoreParams {
    /// The Ethereum parameters, before any topic is added.
    ///
    /// # Arguments
    ///
    /// - `slot`: the slot duration, which is also the decay interval.
    /// - `slots_per_epoch`: the preset epoch length.
    /// - `total_topic_weight`: the sum of the weights of every topic that will be added.
    #[must_use]
    pub fn ethereum(slot: Duration, slots_per_epoch: u32, total_topic_weight: f64) -> Self {
        let epoch = slot * slots_per_epoch;
        let decay_to_zero = 0.01;
        let decay = DecaySchedule {
            interval: slot,
            to_zero: decay_to_zero,
        };
        // The best score a peer can reach: perfect P1 and P2 in every topic.
        let max_positive_score =
            (MAX_IN_MESH_SCORE + MAX_FIRST_MESSAGE_DELIVERIES_SCORE) * total_topic_weight;
        let thresholds = PeerScoreThresholds::ethereum();
        // Ten behaviour penalties beyond the threshold bring a peer to the gossip threshold.
        //
        //     w7 * (16 - 6)^2 = gossip_threshold
        //     w7 = -4000 / 100 = -40
        let behaviour_penalty_threshold = 6.0;
        let behaviour_penalty_weight = thresholds.gossip_threshold / 10.0_f64.powi(2);
        Self {
            topics: BTreeMap::new(),
            topic_score_cap: max_positive_score / 2.0,
            app_specific_weight: 1.0,
            // One surplus peer on an IP cancels a perfect score.
            ip_colocation_factor_weight: -max_positive_score,
            ip_colocation_factor_threshold: 8.0,
            behaviour_penalty_weight,
            behaviour_penalty_threshold,
            behaviour_penalty_decay: decay.factor_over(epoch * 10),
            decay_interval: slot,
            decay_to_zero,
            retain_score: epoch * 100,
        }
    }
}

impl TopicScoreParams {
    /// Ethereum parameters for a topic carrying a given number of messages per slot.
    ///
    /// # Arguments
    ///
    /// - `topic_weight`: the topic's share of the score.
    /// - `messages_per_slot`: the expected network-wide rate.
    /// - `slot`: the slot duration, the decay interval.
    /// - `slots_per_epoch`: the preset epoch length.
    /// - `mesh_n`: the mesh degree, which splits first deliveries among mesh peers.
    ///
    /// # Overview
    ///
    /// Mesh delivery deficits (P3, P3b) are disabled.
    /// On low-rate topics a quiet but honest peer cannot be told from a silent attacker.
    #[must_use]
    pub fn ethereum(
        topic_weight: f64,
        messages_per_slot: f64,
        slot: Duration,
        slots_per_epoch: u32,
        mesh_n: usize,
    ) -> Self {
        let epoch = slot * slots_per_epoch;
        let decay = DecaySchedule {
            interval: slot,
            to_zero: 0.01,
        };
        // P1: one quantum per slot, capped after one hour in the mesh.
        let time_in_mesh_cap = 3600.0 / slot.as_secs_f64();
        // P2: a mesh peer delivers first about 1 / D of the messages.
        //
        //     steady state = rate / D / (1 - decay); cap at twice that
        let first_decay = decay.factor_over(epoch);
        let mesh_n = f64::from(u32::try_from(mesh_n).unwrap_or(u32::MAX));
        // A counter gaining a rate per interval converges where gain equals decay.
        //
        //     c = c * decay + rate
        //     c = rate / (1 - decay)
        let steady_state = (messages_per_slot / mesh_n) / (1.0 - first_decay);
        let first_cap = 2.0 * steady_state.max(1.0);
        Self {
            topic_weight,
            time_in_mesh_weight: MAX_IN_MESH_SCORE / time_in_mesh_cap,
            time_in_mesh_quantum: slot,
            time_in_mesh_cap,
            first_message_deliveries_weight: MAX_FIRST_MESSAGE_DELIVERIES_SCORE / first_cap,
            first_message_deliveries_decay: first_decay,
            first_message_deliveries_cap: first_cap,
            mesh_message_deliveries_weight: 0.0,
            mesh_message_deliveries_decay: decay.factor_over(epoch),
            mesh_message_deliveries_cap: 0.0,
            mesh_message_deliveries_threshold: 0.0,
            mesh_message_deliveries_window: Duration::from_secs(2),
            mesh_message_deliveries_activation: epoch * 4,
            mesh_failure_penalty_weight: 0.0,
            mesh_failure_penalty_decay: decay.factor_over(epoch),
            // P4: ten invalid messages reach the graylist threshold.
            //
            //     topic_weight * w4 * 10^2 = -16000
            //     w4 = -160 / topic_weight
            invalid_message_deliveries_weight: PeerScoreThresholds::ethereum().graylist_threshold
                / 100.0
                / topic_weight.max(f64::EPSILON),
            invalid_message_deliveries_decay: decay.factor_over(epoch * 50),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decay_reaches_the_floor_on_time() {
        // Decaying over 10 intervals: decay^10 = 0.01, so decay = 0.01^(1/10).
        let schedule = DecaySchedule {
            interval: Duration::from_secs(12),
            to_zero: 0.01,
        };
        let decay = schedule.factor_over(Duration::from_secs(120));
        assert!((decay.powi(10) - 0.01).abs() < 1e-12);
    }

    #[test]
    fn ethereum_thresholds_are_ordered() {
        let t = PeerScoreThresholds::ethereum();
        assert!(t.graylist_threshold < t.publish_threshold);
        assert!(t.publish_threshold < t.gossip_threshold);
        assert!(t.gossip_threshold < 0.0);
        assert!(t.accept_px_threshold > 0.0);
    }

    #[test]
    fn ethereum_topic_caps_reach_the_maximum_scores() {
        // A block topic: 1 message per slot, weight 0.5.
        let params = TopicScoreParams::ethereum(0.5, 1.0, Duration::from_secs(12), 32, 8);
        // Full P1 and P2 give 10 + 40 before the topic weight.
        let p1 = params.time_in_mesh_cap * params.time_in_mesh_weight;
        let p2 = params.first_message_deliveries_cap * params.first_message_deliveries_weight;
        assert!((p1 - 10.0).abs() < 1e-9);
        assert!((p2 - 40.0).abs() < 1e-9);
    }
}
