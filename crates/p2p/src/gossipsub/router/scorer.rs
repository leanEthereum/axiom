//! Peer scoring as the router sees it: on or off.

use std::{net::IpAddr, time::Duration};

use crate::{
    gossipsub::{
        MessageId, Topic,
        score::{PeerScore, PeerScoreParams, PeerScoreThresholds, RejectReason},
    },
    identity::PeerId,
};

/// The thresholds in force without scoring: nothing is ever restricted.
const UNRESTRICTED: PeerScoreThresholds = PeerScoreThresholds {
    gossip_threshold: f64::NEG_INFINITY,
    publish_threshold: f64::NEG_INFINITY,
    graylist_threshold: f64::NEG_INFINITY,
    accept_px_threshold: 0.0,
    opportunistic_graft_threshold: f64::NEG_INFINITY,
};

/// The peer scorer and its thresholds, or nothing when scoring is off.
///
/// With scoring off, every peer scores zero and every report is dropped.
#[derive(Clone, Debug)]
pub(super) struct Scorer {
    /// Counters and score function, with the restriction levels they are compared against.
    scoring: Option<(PeerScore, PeerScoreThresholds)>,
}

impl Scorer {
    /// A scorer with the given parameters, or a disabled one.
    pub(super) fn new(scoring: Option<(PeerScoreParams, PeerScoreThresholds)>) -> Self {
        Self {
            scoring: scoring.map(|(params, thresholds)| (PeerScore::new(params), thresholds)),
        }
    }

    /// Whether scoring is on.
    pub(super) const fn is_enabled(&self) -> bool {
        self.scoring.is_some()
    }

    /// A peer's current score, zero when scoring is off.
    pub(super) fn score(&self, peer: &PeerId, now: Duration) -> f64 {
        self.scoring
            .as_ref()
            .map_or(0.0, |(score, _)| score.score(peer, now))
    }

    /// The thresholds in force.
    pub(super) fn thresholds(&self) -> PeerScoreThresholds {
        self.scoring
            .as_ref()
            .map_or(UNRESTRICTED, |(_, thresholds)| *thresholds)
    }

    /// Starts tracking a connected peer.
    pub(super) fn add_peer(&mut self, peer: PeerId) {
        if let Some((score, _)) = &mut self.scoring {
            score.add_peer(peer);
        }
    }

    /// Marks a peer disconnected.
    pub(super) fn remove_peer(&mut self, peer: &PeerId, now: Duration) {
        if let Some((score, _)) = &mut self.scoring {
            score.remove_peer(peer, now);
        }
    }

    /// Records a peer's IP address, for the colocation term.
    pub(super) fn set_ip(&mut self, peer: &PeerId, ip: IpAddr) {
        if let Some((score, _)) = &mut self.scoring {
            score.set_ip(peer, ip);
        }
    }

    /// Sets the application-specific term of a peer.
    pub(super) fn set_application_score(&mut self, peer: &PeerId, value: f64) {
        if let Some((score, _)) = &mut self.scoring {
            score.set_application_score(peer, value);
        }
    }

    /// Adds behaviour penalties to a peer.
    pub(super) fn add_penalty(&mut self, peer: &PeerId, count: usize) {
        if let Some((score, _)) = &mut self.scoring {
            score.add_penalty(peer, count);
        }
    }

    /// Records a peer joining a mesh.
    pub(super) fn graft(&mut self, peer: &PeerId, topic: &Topic, now: Duration) {
        if let Some((score, _)) = &mut self.scoring {
            score.graft(peer, topic, now);
        }
    }

    /// Records a peer leaving a mesh.
    pub(super) fn prune(&mut self, peer: &PeerId, topic: &Topic) {
        if let Some((score, _)) = &mut self.scoring {
            score.prune(peer, topic);
        }
    }

    /// Records a new message entering validation.
    pub(super) fn validate_message(&mut self, id: MessageId, now: Duration) {
        if let Some((score, _)) = &mut self.scoring {
            score.validate_message(id, now);
        }
    }

    /// Credits the first deliverer of an accepted message.
    pub(super) fn deliver_message(
        &mut self,
        from: &PeerId,
        id: MessageId,
        topic: &Topic,
        now: Duration,
    ) {
        if let Some((score, _)) = &mut self.scoring {
            score.deliver_message(from, id, topic, now);
        }
    }

    /// Charges the deliverer of a message the application refused.
    pub(super) fn reject_message(
        &mut self,
        from: &PeerId,
        id: Option<MessageId>,
        topic: &Topic,
        reason: RejectReason,
    ) {
        if let Some((score, _)) = &mut self.scoring {
            score.reject_message(from, id, topic, reason);
        }
    }

    /// Records a duplicate delivery.
    pub(super) fn duplicated_message(
        &mut self,
        from: &PeerId,
        id: MessageId,
        topic: &Topic,
        now: Duration,
    ) {
        if let Some((score, _)) = &mut self.scoring {
            score.duplicated_message(from, id, topic, now);
        }
    }

    /// Decays the counters and drops expired records.
    pub(super) fn refresh(&mut self, now: Duration) {
        if let Some((score, _)) = &mut self.scoring {
            score.refresh(now);
        }
    }
}
