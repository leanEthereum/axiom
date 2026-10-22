//! Loss detection and congestion control, per RFC 9002.
//!
//! # Overview
//!
//! Every packet that carries more than acknowledgments is tracked until the peer acknowledges it.
//! A packet is declared lost by one of two rules, per section 6.1:
//!
//! - a packet three numbers newer was acknowledged
//! - a newer packet was acknowledged and 9/8 of an RTT has passed since this one was sent
//!
//! When no acknowledgment arrives at all, the probe timeout fires and the sender probes.
//! Each consecutive probe timeout doubles the next one.
//!
//! The three packet number spaces track their packets separately and share one RTT estimate.

mod congestion;
mod rtt;
mod sent;

use std::{collections::BTreeMap, mem, time::Duration};

pub(crate) use congestion::NewReno;
pub(crate) use rtt::RttEstimator;
pub(crate) use sent::{SentFrame, SentPacket};

use super::{TransportError, frame::AckFrame, packet::PacketNumber, space::Space};

/// Packets a newer acknowledgment must pass before an older one is lost, per RFC 9002, section 6.1.1.
const PACKET_THRESHOLD: u64 = 3;

/// Probe timeouts a loss span must cover to signal persistent congestion, per RFC 9002, section 7.6.1.
const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

/// The loss detection state of one packet number space.
#[derive(Debug, Default)]
struct SpaceRecovery {
    /// Packets in flight or awaiting acknowledgment, by number.
    sent: BTreeMap<PacketNumber, SentPacket>,
    /// The largest number the peer acknowledged.
    largest_acked: Option<PacketNumber>,
    /// When the earliest packet becomes lost by the time threshold.
    loss_time: Option<Duration>,
    /// When the last ack-eliciting packet was sent.
    last_ack_eliciting: Option<Duration>,
    /// Ack-eliciting packets awaiting acknowledgment.
    ack_eliciting_in_flight: usize,
}

impl SpaceRecovery {
    /// Removes a packet from tracking.
    fn remove(&mut self, number: PacketNumber) -> Option<SentPacket> {
        let packet = self.sent.remove(&number)?;
        if packet.ack_eliciting {
            self.ack_eliciting_in_flight -= 1;
        }
        Some(packet)
    }
}

/// What an acknowledgment did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct AckOutcome {
    /// Packets newly acknowledged.
    pub(crate) acked: Vec<SentPacket>,
    /// Packets newly declared lost.
    pub(crate) lost: Vec<SentPacket>,
}

/// What the loss detection timer asks for when it fires.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TimerAction {
    /// Packets of a space passed the time threshold and are lost.
    Lost(Space, Vec<SentPacket>),
    /// Send one or two ack-eliciting probes in a space.
    Probe(Space),
}

/// The facts about the connection that steer the timer, per RFC 9002, appendix A.8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "four independent facts of the pseudocode, each a yes or no"
)]
pub(crate) struct TimerContext {
    /// Whether the handshake is confirmed, which unlocks probes of 1-RTT data.
    pub(crate) handshake_confirmed: bool,
    /// Whether the peer has validated this side's address; always true for servers.
    pub(crate) peer_validated: bool,
    /// Whether Handshake keys are available.
    pub(crate) has_handshake_keys: bool,
    /// Whether a server cannot send for the amplification limit.
    pub(crate) amplification_blocked: bool,
}

/// Loss detection over the three spaces, with the congestion controller.
#[derive(Debug)]
pub(crate) struct Recovery {
    /// The RTT estimate.
    pub(crate) rtt: RttEstimator,
    /// The congestion controller.
    pub(crate) congestion: NewReno,
    /// Per-space state.
    spaces: [SpaceRecovery; 3],
    /// Consecutive probe timeouts.
    pto_count: u32,
    /// The peer's max_ack_delay, which pads 1-RTT probe timeouts.
    max_ack_delay: Duration,
}

impl Recovery {
    /// Fresh state for datagrams of a size.
    pub(crate) fn new(max_datagram: u64) -> Self {
        Self {
            rtt: RttEstimator::default(),
            congestion: NewReno::new(max_datagram),
            spaces: Default::default(),
            pto_count: 0,
            max_ack_delay: Duration::ZERO,
        }
    }

    /// Records the peer's max_ack_delay from its transport parameters.
    pub(crate) const fn set_max_ack_delay(&mut self, delay: Duration) {
        self.max_ack_delay = delay;
    }

    /// The current probe timeout with the peer's ack delay, without backoff.
    pub(crate) fn pto(&self) -> Duration {
        self.rtt.pto_base() + self.max_ack_delay
    }

    /// Tracks a sent packet.
    pub(crate) fn on_sent(&mut self, space: Space, packet: SentPacket) {
        let state = &mut self.spaces[space.index()];
        if packet.in_flight {
            self.congestion.on_sent(packet.size);
        }
        if packet.ack_eliciting {
            state.last_ack_eliciting = Some(packet.time_sent);
            state.ack_eliciting_in_flight += 1;
        }
        state.sent.insert(packet.number, packet);
    }

    /// Whether ack-eliciting packets await acknowledgment in any space.
    fn ack_eliciting_in_flight(&self) -> bool {
        self.spaces
            .iter()
            .any(|space| space.ack_eliciting_in_flight > 0)
    }

    /// Applies an acknowledgment.
    ///
    /// # Arguments
    ///
    /// - `ack_delay`: the peer's reported delay, already decoded with its exponent.
    /// - `context`: whether the handshake is confirmed caps the delay at max_ack_delay.
    ///
    /// # Errors
    ///
    /// Fails with PROTOCOL_VIOLATION when the frame acknowledges a number never sent.
    pub(crate) fn on_ack(
        &mut self,
        space: Space,
        ack: &AckFrame,
        ack_delay: Duration,
        now: Duration,
        context: TimerContext,
    ) -> Result<AckOutcome, TransportError> {
        let largest = PacketNumber(ack.largest());
        let state = &mut self.spaces[space.index()];
        let next_unsent = state
            .sent
            .last_key_value()
            .map_or(PacketNumber(0), |(number, _)| number.next());
        if largest >= next_unsent && state.largest_acked.is_none_or(|acked| largest > acked) {
            return Err(TransportError::protocol(format!(
                "acknowledgment of unsent packet {} in the {space:?} space",
                largest.0
            )));
        }
        state.largest_acked = Some(
            state
                .largest_acked
                .map_or(largest, |acked| acked.max(largest)),
        );

        let mut outcome = AckOutcome::default();
        for range in &ack.ranges {
            let numbers: Vec<PacketNumber> = state
                .sent
                .range(PacketNumber(range.start)..PacketNumber(range.end))
                .map(|(number, _)| *number)
                .collect();
            for number in numbers {
                if let Some(packet) = state.remove(number) {
                    outcome.acked.push(packet);
                }
            }
        }
        if outcome.acked.is_empty() {
            return Ok(outcome);
        }

        // An RTT sample comes only from the largest number, newly acknowledged and ack-eliciting.
        let newest = outcome.acked.iter().max_by_key(|packet| packet.number);
        if let Some(newest) = newest
            && newest.number == largest
            && outcome.acked.iter().any(|packet| packet.ack_eliciting)
        {
            let delay = if context.handshake_confirmed {
                ack_delay.min(self.max_ack_delay)
            } else {
                ack_delay
            };
            // Initial and Handshake acknowledgments are sent at once, so their delay is ignored.
            let delay = if space == Space::Data {
                delay
            } else {
                Duration::ZERO
            };
            self.rtt.update(now.saturating_sub(newest.time_sent), delay);
        }

        outcome.lost = self.detect_lost(space, now);
        self.on_packets_lost(&outcome.lost, &outcome.acked, now);
        for packet in &outcome.acked {
            if packet.in_flight {
                self.congestion.on_acked(packet.size, packet.time_sent);
            }
        }
        if context.peer_validated {
            self.pto_count = 0;
        }
        Ok(outcome)
    }

    /// Removes and returns the packets of a space that the thresholds declare lost.
    fn detect_lost(&mut self, space: Space, now: Duration) -> Vec<SentPacket> {
        let loss_delay = self.rtt.loss_delay();
        let state = &mut self.spaces[space.index()];
        state.loss_time = None;
        let Some(largest) = state.largest_acked else {
            return Vec::new();
        };
        let lost_before = now.saturating_sub(loss_delay);
        let mut lost = Vec::new();
        let candidates: Vec<(PacketNumber, Duration)> = state
            .sent
            .range(..=largest)
            .map(|(number, packet)| (*number, packet.time_sent))
            .collect();
        for (number, time_sent) in candidates {
            if time_sent <= lost_before || largest.0 >= number.0 + PACKET_THRESHOLD {
                if let Some(packet) = state.remove(number) {
                    lost.push(packet);
                }
            } else {
                let at = time_sent + loss_delay;
                state.loss_time = Some(state.loss_time.map_or(at, |time| time.min(at)));
            }
        }
        lost
    }

    /// Feeds lost packets to the congestion controller, checking for persistent congestion.
    fn on_packets_lost(&mut self, lost: &[SentPacket], acked: &[SentPacket], now: Duration) {
        let in_flight: Vec<&SentPacket> = lost.iter().filter(|packet| packet.in_flight).collect();
        for packet in &in_flight {
            self.congestion.on_lost(packet.size);
        }
        let Some(latest) = in_flight.iter().map(|packet| packet.time_sent).max() else {
            return;
        };
        self.congestion.on_congestion(latest, now);

        // Persistent congestion: ack-eliciting losses spanning three probe timeouts, nothing acknowledged between.
        let eliciting = lost.iter().filter(|packet| packet.ack_eliciting);
        let first = eliciting.clone().map(|packet| packet.time_sent).min();
        let last = eliciting.map(|packet| packet.time_sent).max();
        if let (Some(first), Some(last)) = (first, last)
            && self.rtt.has_sample()
        {
            let duration = self.pto() * PERSISTENT_CONGESTION_THRESHOLD;
            let acked_between = acked
                .iter()
                .any(|packet| packet.time_sent > first && packet.time_sent < last);
            if last.saturating_sub(first) >= duration && !acked_between {
                self.congestion.on_persistent_congestion();
            }
        }
    }

    /// When the loss detection timer fires, if it is armed.
    pub(crate) fn timer(&self, context: TimerContext, now: Duration) -> Option<Duration> {
        if let Some((time, _)) = self.earliest_loss_time() {
            return Some(time);
        }
        if context.amplification_blocked {
            return None;
        }
        if !self.ack_eliciting_in_flight() && context.peer_validated {
            return None;
        }
        self.pto_time(context, now).map(|(time, _)| time)
    }

    /// The earliest time-threshold loss and its space.
    fn earliest_loss_time(&self) -> Option<(Duration, Space)> {
        Space::ALL
            .into_iter()
            .filter_map(|space| {
                self.spaces[space.index()]
                    .loss_time
                    .map(|time| (time, space))
            })
            .min()
    }

    /// The probe timeout and the space it probes, per RFC 9002, appendix A.8.
    fn pto_time(&self, context: TimerContext, now: Duration) -> Option<(Duration, Space)> {
        let backoff = 1_u32 << self.pto_count.min(16);
        let duration = self.rtt.pto_base() * backoff;
        if !self.ack_eliciting_in_flight() {
            // Anti-deadlock: the client probes so the server can earn amplification credit.
            let space = if context.has_handshake_keys {
                Space::Handshake
            } else {
                Space::Initial
            };
            return Some((now + duration, space));
        }
        let mut best: Option<(Duration, Space)> = None;
        for space in Space::ALL {
            let state = &self.spaces[space.index()];
            if state.ack_eliciting_in_flight == 0 {
                continue;
            }
            let mut duration = duration;
            if space == Space::Data {
                if !context.handshake_confirmed {
                    break;
                }
                duration += self.max_ack_delay * backoff;
            }
            let Some(last) = state.last_ack_eliciting else {
                continue;
            };
            let time = last + duration;
            if best.is_none_or(|(best, _)| time < best) {
                best = Some((time, space));
            }
        }
        best
    }

    /// Handles the loss detection timer firing.
    pub(crate) fn on_timeout(
        &mut self,
        context: TimerContext,
        now: Duration,
    ) -> Option<TimerAction> {
        if let Some((_, space)) = self.earliest_loss_time() {
            let lost = self.detect_lost(space, now);
            self.on_packets_lost(&lost, &[], now);
            return Some(TimerAction::Lost(space, lost));
        }
        let (_, space) = self.pto_time(context, now)?;
        self.pto_count += 1;
        Some(TimerAction::Probe(space))
    }

    /// Forgets a space whose keys were discarded, returning its packets without declaring them lost.
    pub(crate) fn discard(&mut self, space: Space) -> Vec<SentPacket> {
        let state = &mut self.spaces[space.index()];
        let packets: Vec<SentPacket> = mem::take(&mut state.sent).into_values().collect();
        *state = SpaceRecovery::default();
        for packet in &packets {
            if packet.in_flight {
                self.congestion.on_discarded(packet.size);
            }
        }
        self.pto_count = 0;
        packets
    }

    /// Unacknowledged packets of a space, oldest first, for probes that repeat their data.
    pub(crate) fn unacked(&self, space: Space) -> impl Iterator<Item = &SentPacket> {
        self.spaces[space.index()].sent.values()
    }
}

#[cfg(test)]
mod tests {
    use std::{iter, ops::Range};

    use super::*;
    use crate::quic::TransportErrorCode;

    const MS: Duration = Duration::from_millis(1);

    const CONTEXT: TimerContext = TimerContext {
        handshake_confirmed: true,
        peer_validated: true,
        has_handshake_keys: true,
        amplification_blocked: false,
    };

    fn packet(number: u64, time_sent: Duration) -> SentPacket {
        SentPacket {
            number: PacketNumber(number),
            time_sent,
            size: 1200,
            ack_eliciting: true,
            in_flight: true,
            frames: vec![SentFrame::Ping],
        }
    }

    /// An acknowledgment of one range.
    fn ack(range: Range<u64>) -> AckFrame {
        AckFrame {
            ranges: iter::once(range).collect(),
            delay: 0,
            ecn: None,
        }
    }

    fn numbers(packets: &[SentPacket]) -> Vec<u64> {
        packets.iter().map(|packet| packet.number.0).collect()
    }

    #[test]
    fn packet_threshold_declares_loss() {
        let mut recovery = Recovery::new(1200);
        for number in 0..5 {
            recovery.on_sent(Space::Data, packet(number, MS * number as u32));
        }
        // Acknowledging 3 and 4 at 30 ms: packets 0 and 1 trail by three or more, 2 by two.
        let outcome = recovery
            .on_ack(Space::Data, &ack(3..5), Duration::ZERO, 30 * MS, CONTEXT)
            .unwrap();
        assert_eq!(numbers(&outcome.acked), [3, 4]);
        assert_eq!(numbers(&outcome.lost), [0, 1]);

        // Packet 2 waits for the time threshold: 9/8 of the 26 ms sample after its send at 2 ms.
        let timer = recovery.timer(CONTEXT, 30 * MS).unwrap();
        assert_eq!(timer, 2 * MS + Duration::from_micros(29_250));
        assert_eq!(
            recovery
                .on_timeout(CONTEXT, timer)
                .map(|action| match action {
                    TimerAction::Lost(_, lost) => numbers(&lost),
                    TimerAction::Probe(_) => Vec::new(),
                }),
            Some(vec![2])
        );
    }

    #[test]
    fn acknowledging_an_unsent_packet_is_a_violation() {
        let mut recovery = Recovery::new(1200);
        recovery.on_sent(Space::Initial, packet(0, Duration::ZERO));
        assert_eq!(
            recovery
                .on_ack(Space::Initial, &ack(0..2), Duration::ZERO, MS, CONTEXT)
                .map_err(|error| error.code),
            Err(TransportErrorCode::PROTOCOL_VIOLATION)
        );
    }

    #[test]
    fn probe_timeout_backs_off() {
        let mut recovery = Recovery::new(1200);
        recovery.set_max_ack_delay(25 * MS);
        recovery.on_sent(Space::Data, packet(0, Duration::ZERO));
        // No RTT sample: 333 ms + 4 * 166.5 ms + 25 ms = 1024 ms.
        assert_eq!(recovery.timer(CONTEXT, Duration::ZERO), Some(1024 * MS));
        assert_eq!(
            recovery.on_timeout(CONTEXT, 1024 * MS),
            Some(TimerAction::Probe(Space::Data))
        );
        // The second timeout doubles: 2048 ms after the send.
        assert_eq!(recovery.timer(CONTEXT, 1024 * MS), Some(2048 * MS));
        assert_eq!(recovery.pto_count, 1);
    }

    #[test]
    fn handshake_data_is_not_probed_before_confirmation() {
        let mut recovery = Recovery::new(1200);
        recovery.on_sent(Space::Data, packet(0, Duration::ZERO));
        let unconfirmed = TimerContext {
            handshake_confirmed: false,
            ..CONTEXT
        };
        assert_eq!(recovery.timer(unconfirmed, Duration::ZERO), None);

        // A client without validation arms the anti-deadlock timer with nothing in flight.
        let mut client = Recovery::new(1200);
        let unvalidated = TimerContext {
            peer_validated: false,
            has_handshake_keys: false,
            ..unconfirmed
        };
        assert_eq!(client.timer(unvalidated, 5 * MS), Some(5 * MS + 999 * MS));
        assert_eq!(
            client.on_timeout(unvalidated, 1004 * MS),
            Some(TimerAction::Probe(Space::Initial))
        );
    }

    #[test]
    fn persistent_congestion_collapses_the_window() {
        let mut recovery = Recovery::new(1200);
        // An RTT sample of 10 ms from packet 0.
        recovery.on_sent(Space::Data, packet(0, Duration::ZERO));
        recovery
            .on_ack(Space::Data, &ack(0..1), Duration::ZERO, 10 * MS, CONTEXT)
            .unwrap();
        // Packets 1 to 4 sent across 400 ms, then packet 5 acknowledged.
        for number in 1..5 {
            recovery.on_sent(Space::Data, packet(number, MS * 100 * number as u32));
        }
        recovery.on_sent(Space::Data, packet(5, 500 * MS));
        let outcome = recovery
            .on_ack(Space::Data, &ack(5..6), Duration::ZERO, 510 * MS, CONTEXT)
            .unwrap();
        // Losses from 100 to 400 ms span 300 ms, beyond 3 * (10 + 20) ms.
        // The window collapses to 2400, then slow start credits packet 5's 1200 bytes.
        assert_eq!(numbers(&outcome.lost), [1, 2, 3, 4]);
        assert_eq!(recovery.congestion.window(), 3600);
    }

    #[test]
    fn discarding_a_space_drops_its_flight() {
        let mut recovery = Recovery::new(1200);
        recovery.on_sent(Space::Initial, packet(0, Duration::ZERO));
        recovery.on_sent(Space::Initial, packet(1, MS));
        assert_eq!(recovery.congestion.in_flight(), 2400);
        assert_eq!(numbers(&recovery.discard(Space::Initial)), [0, 1]);
        assert_eq!(recovery.congestion.in_flight(), 0);
        assert_eq!(recovery.timer(CONTEXT, MS), None);
    }
}
