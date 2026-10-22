//! A peer's standing: penalties for misbehaviour that fade with time.
//!
//! # Overview
//!
//! Each fault costs points by its severity.
//! The score decays back towards zero with a fixed half-life, so old faults are forgiven.
//!
//! ```text
//! score(t) = score(t0) * 2^(-(t - t0) / half_life)
//! ```
//!
//! Two thresholds act on it:
//!
//! - at or below the disconnect threshold the peer is dropped, and may reconnect later
//! - at or below the ban threshold the peer is dropped and refused
//!
//! The gossipsub router's own score adds in, scaled so that the worst gossip score alone stays
//! just short of a disconnect.
//!
//! Crossing the ban threshold freezes the decay for 12 hours.
//! The ban lifts once the frozen score has then decayed back above the threshold.
//!
//! Adversary: a peer that sends bad data now and then must not keep its slot.
//! An honest peer that times out once in a while must never reach the thresholds.
//! With a 10 minute half-life, a fault a minute settles near 15 points, safely inside both.

use std::time::Duration;

/// The lowest score; a fatal fault lands here at once.
const MIN_SCORE: f64 = -100.0;

/// At or below this score the peer is disconnected.
const DISCONNECT_THRESHOLD: f64 = -20.0;

/// At or below this score the peer is banned.
const BAN_THRESHOLD: f64 = -50.0;

/// The time for a penalty to halve.
const HALF_LIFE: Duration = Duration::from_mins(10);

/// How long a fresh ban holds the score before it decays.
const BAN_FREEZE: Duration = Duration::from_hours(12);

/// Below this local score, the gossip score no longer counts: the peer is banned on local faults.
const LOCAL_BAN_FLOOR: f64 = -60.0;

/// The gossipsub graylist threshold of the Ethereum scoring parameters.
const GOSSIP_GRAYLIST_THRESHOLD: f64 = -16000.0;

/// The weight of the gossip score: a graylisted peer lands one point above the disconnect threshold.
const GOSSIP_WEIGHT: f64 = (DISCONNECT_THRESHOLD + 1.0) / GOSSIP_GRAYLIST_THRESHOLD;

/// How severe a fault is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum PeerAction {
    /// Proof of malice or of a broken peer, such as undecodable data: ban at once.
    Fatal,
    /// A fault an honest peer rarely makes, such as a faulty batch.
    LowTolerance,
    /// A fault an honest peer makes under load, such as exceeding a rate limit.
    MidTolerance,
    /// A fault of the network as much as the peer.
    HighTolerance,
}

impl PeerAction {
    /// Points the fault costs.
    const fn penalty(self) -> f64 {
        match self {
            Self::Fatal => -MIN_SCORE,
            Self::LowTolerance => 10.0,
            Self::MidTolerance => 5.0,
            Self::HighTolerance => 1.0,
        }
    }

    /// The label metrics use.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Fatal => "fatal",
            Self::LowTolerance => "low_tolerance",
            Self::MidTolerance => "mid_tolerance",
            Self::HighTolerance => "high_tolerance",
        }
    }
}

/// What a score asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Standing {
    /// The peer may stay.
    Good,
    /// The peer must be disconnected.
    Disconnect,
    /// The peer must be disconnected and refused.
    Ban,
}

/// A decaying score of local faults, combined with the router's gossip score.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct PeerScore {
    /// The local score at the reference time.
    value: f64,
    /// The time decay counts from; a ban moves it into the future.
    updated: Duration,
    /// The gossipsub router's latest score.
    gossip: f64,
    /// Whether a negative gossip score is ignored, so the peer can recover in the mesh.
    ignore_negative_gossip: bool,
}

impl PeerScore {
    /// A clean score.
    pub(crate) const fn new(now: Duration) -> Self {
        Self {
            value: 0.0,
            updated: now,
            gossip: 0.0,
            ignore_negative_gossip: false,
        }
    }

    /// The local score at a time, decayed since the reference time.
    fn local_at(&self, now: Duration) -> f64 {
        let elapsed = now.saturating_sub(self.updated).as_secs_f64();
        self.value * (-elapsed / HALF_LIFE.as_secs_f64()).exp2()
    }

    /// The combined score at a time.
    pub(crate) fn at(&self, now: Duration) -> f64 {
        let local = self.local_at(now);
        if local <= LOCAL_BAN_FLOOR || (self.gossip < 0.0 && self.ignore_negative_gossip) {
            return local;
        }
        self.gossip.mul_add(GOSSIP_WEIGHT, local)
    }

    /// Applies a fault and returns the standing it leaves.
    pub(crate) fn apply(&mut self, action: PeerAction, now: Duration) -> Standing {
        let before = self.at(now);
        self.value = (self.local_at(now) - action.penalty()).max(MIN_SCORE);
        // A frozen score keeps its freeze; otherwise decay restarts from now.
        self.updated = self.updated.max(now);
        self.freeze_on_ban(before, now);
        self.standing(now)
    }

    /// Takes the router's gossip score and returns the standing it leaves.
    pub(crate) fn set_gossip(
        &mut self,
        gossip: f64,
        ignore_negative: bool,
        now: Duration,
    ) -> Standing {
        let before = self.at(now);
        self.gossip = gossip;
        self.ignore_negative_gossip = ignore_negative;
        self.freeze_on_ban(before, now);
        self.standing(now)
    }

    /// Freezes the local score for twelve hours when the combined score just crossed into a ban.
    fn freeze_on_ban(&mut self, before: f64, now: Duration) {
        if before > BAN_THRESHOLD && self.at(now) <= BAN_THRESHOLD {
            self.value = self.local_at(now);
            self.updated = now + BAN_FREEZE;
        }
    }

    /// The standing at a time.
    pub(crate) fn standing(&self, now: Duration) -> Standing {
        let score = self.at(now);
        if score <= BAN_THRESHOLD {
            Standing::Ban
        } else if score <= DISCONNECT_THRESHOLD {
            Standing::Disconnect
        } else {
            Standing::Good
        }
    }

    /// Whether the score has decayed back to practically clean.
    pub(crate) fn is_forgiven(&self, now: Duration) -> bool {
        self.at(now) > -1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_mins(1);

    #[test]
    fn faults_accumulate_and_cross_the_thresholds() {
        let mut score = PeerScore::new(Duration::ZERO);
        // Two low-tolerance faults at once: -20, the disconnect threshold.
        assert_eq!(
            score.apply(PeerAction::LowTolerance, Duration::ZERO),
            Standing::Good
        );
        assert_eq!(
            score.apply(PeerAction::LowTolerance, Duration::ZERO),
            Standing::Disconnect
        );
        // Three more reach -50: a ban.
        for _ in 0..2 {
            score.apply(PeerAction::LowTolerance, Duration::ZERO);
        }
        assert_eq!(
            score.apply(PeerAction::LowTolerance, Duration::ZERO),
            Standing::Ban
        );
        // A fatal fault bans a clean peer outright.
        let mut clean = PeerScore::new(Duration::ZERO);
        assert_eq!(
            clean.apply(PeerAction::Fatal, Duration::ZERO),
            Standing::Ban
        );
        assert_eq!(clean.at(Duration::ZERO), MIN_SCORE);
    }

    #[test]
    fn a_ban_freezes_the_score_for_twelve_hours_then_decays() {
        let mut score = PeerScore::new(Duration::ZERO);
        score.apply(PeerAction::Fatal, Duration::ZERO);
        // Twelve hours on, the score is still -100.
        assert_eq!(score.at(BAN_FREEZE), MIN_SCORE);
        // Then it halves every ten minutes: -50 is still a ban, -25 is not.
        assert_eq!(score.standing(BAN_FREEZE + 10 * MINUTE), Standing::Ban);
        assert_eq!(
            score.standing(BAN_FREEZE + 20 * MINUTE),
            Standing::Disconnect
        );
        assert_eq!(score.standing(BAN_FREEZE + 30 * MINUTE), Standing::Good);
        assert!(score.is_forgiven(BAN_FREEZE + 70 * MINUTE));
    }

    #[test]
    fn the_gossip_score_counts_but_never_disconnects_alone() {
        let mut score = PeerScore::new(Duration::ZERO);
        // A graylisted gossip score of -16000 alone gives -19: still good.
        assert_eq!(
            score.set_gossip(-16_000.0, false, Duration::ZERO),
            Standing::Good
        );
        assert_eq!(score.at(Duration::ZERO), -19.0);
        // One more local fault tips it into a disconnect.
        assert_eq!(
            score.apply(PeerAction::HighTolerance, Duration::ZERO),
            Standing::Disconnect
        );
        // Ignored, the negative gossip score no longer counts.
        assert_eq!(
            score.set_gossip(-16_000.0, true, Duration::ZERO),
            Standing::Good
        );
        assert_eq!(score.at(Duration::ZERO), -1.0);
        // A positive gossip score offsets local faults.
        assert_eq!(
            score.set_gossip(1600.0, false, Duration::ZERO),
            Standing::Good
        );
        assert!((score.at(Duration::ZERO) - 0.9).abs() < 1e-9);
    }

    #[test]
    fn penalties_halve_every_ten_minutes() {
        let mut score = PeerScore::new(Duration::ZERO);
        // Two low-tolerance faults: -20, which halves to -10 after ten minutes.
        score.apply(PeerAction::LowTolerance, Duration::ZERO);
        score.apply(PeerAction::LowTolerance, Duration::ZERO);
        assert_eq!(score.at(10 * MINUTE), -10.0);
        assert_eq!(score.at(20 * MINUTE), -5.0);
    }

    #[test]
    fn an_honest_peer_timing_out_every_minute_stays() {
        // One timeout a minute for five hours settles near 1 / (1 - 2^(-1/10)), about 15 points.
        let mut score = PeerScore::new(Duration::ZERO);
        let mut standing = Standing::Good;
        for minute in 0..300 {
            standing = score.apply(PeerAction::HighTolerance, MINUTE * minute);
        }
        assert_eq!(standing, Standing::Good);
        assert!(score.at(MINUTE * 300) > DISCONNECT_THRESHOLD);
    }
}
