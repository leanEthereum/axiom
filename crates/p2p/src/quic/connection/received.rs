//! Received packet numbers of one space, and when to acknowledge them.
//!
//! The acknowledgment policy follows RFC 9000, section 13.2:
//!
//! - Initial and Handshake packets are acknowledged at once.
//! - 1-RTT packets are acknowledged after every second ack-eliciting packet, or after max_ack_delay.
//! - A packet that arrives out of order is acknowledged at once, so the sender learns of the gap.

use std::time::Duration;

use crate::quic::{frame::AckFrame, packet::PacketNumber, range_set::RangeSet};

/// Ranges reported per acknowledgment; older ranges are dropped.
///
/// Threshold: 32 gaps cover any reordering this transport meets, and keep ACK frames small.
const MAX_RANGES: usize = 32;

/// Ack-eliciting 1-RTT packets that trigger an immediate acknowledgment.
const ACK_ELICITING_THRESHOLD: u32 = 2;

/// The received packet numbers of one space.
#[derive(Debug, Default)]
pub(crate) struct ReceivedPackets {
    /// Every number received, as ranges.
    ranges: RangeSet,
    /// The largest number received, and when.
    largest: Option<(PacketNumber, Duration)>,
    /// Ack-eliciting packets since the last acknowledgment.
    unacked_eliciting: u32,
    /// Whether an acknowledgment must go out now.
    immediate: bool,
    /// When a delayed acknowledgment falls due.
    deadline: Option<Duration>,
    /// Whether any packet arrived since the last acknowledgment.
    fresh: bool,
}

impl ReceivedPackets {
    /// The largest number received.
    pub(crate) fn largest(&self) -> Option<PacketNumber> {
        self.largest.map(|(number, _)| number)
    }

    /// Whether a number was already received.
    pub(crate) fn is_duplicate(&self, number: PacketNumber) -> bool {
        self.ranges.contains(number.0)
    }

    /// Records a received packet.
    ///
    /// # Arguments
    ///
    /// - `eager`: acknowledge every ack-eliciting packet at once, as Initial and Handshake spaces do.
    /// - `max_ack_delay`: the longest this side waits otherwise.
    pub(crate) fn on_received(
        &mut self,
        number: PacketNumber,
        ack_eliciting: bool,
        now: Duration,
        eager: bool,
        max_ack_delay: Duration,
    ) {
        // A number below the largest, or one that skips numbers, reveals reordering or loss.
        let out_of_order = self
            .largest
            .is_some_and(|(largest, _)| number.0 != largest.0 + 1);
        self.ranges.insert(number.0..number.0 + 1);
        while self.ranges.range_count() > MAX_RANGES {
            self.ranges.pop_min();
        }
        if self.largest.is_none_or(|(largest, _)| number > largest) {
            self.largest = Some((number, now));
        }
        self.fresh = true;
        if !ack_eliciting {
            return;
        }
        self.unacked_eliciting += 1;
        if eager || out_of_order || self.unacked_eliciting >= ACK_ELICITING_THRESHOLD {
            self.immediate = true;
        } else if self.deadline.is_none() {
            self.deadline = Some(now + max_ack_delay);
        }
    }

    /// Whether an acknowledgment must go out now.
    pub(crate) fn ack_due(&self, now: Duration) -> bool {
        self.immediate || self.deadline.is_some_and(|deadline| deadline <= now)
    }

    /// When a delayed acknowledgment falls due.
    pub(crate) const fn deadline(&self) -> Option<Duration> {
        if self.immediate { None } else { self.deadline }
    }

    /// Whether an acknowledgment may ride along with other frames.
    pub(crate) const fn can_piggyback(&self) -> bool {
        self.fresh
    }

    /// The acknowledgment of what was received, without changing the policy.
    ///
    /// # Arguments
    ///
    /// - `exponent`: this side's ack_delay_exponent, which scales the delay field.
    pub(crate) fn ack_frame(&self, now: Duration, exponent: u32) -> Option<AckFrame> {
        let (_, received_at) = self.largest?;
        let delay = now.saturating_sub(received_at);
        let delay = u64::try_from(delay.as_micros()).unwrap_or(u64::MAX) >> exponent;
        AckFrame::from_ranges(&self.ranges, delay, MAX_RANGES)
    }

    /// Resets the policy once an acknowledgment went out.
    pub(crate) const fn on_ack_sent(&mut self) {
        self.unacked_eliciting = 0;
        self.immediate = false;
        self.deadline = None;
        self.fresh = false;
    }

    /// Builds an acknowledgment and resets the policy, for tests.
    #[cfg(test)]
    fn take_ack(&mut self, now: Duration, exponent: u32) -> Option<AckFrame> {
        let frame = self.ack_frame(now, exponent)?;
        self.on_ack_sent();
        Some(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);
    const DELAY: Duration = Duration::from_millis(25);

    #[test]
    fn every_second_packet_or_after_the_delay() {
        let mut received = ReceivedPackets::default();
        received.on_received(PacketNumber(0), true, Duration::ZERO, false, DELAY);
        // One packet: wait up to 25 ms.
        assert!(!received.ack_due(MS));
        assert_eq!(received.deadline(), Some(DELAY));
        assert!(received.ack_due(DELAY));

        // A second ack-eliciting packet makes it due at once.
        received.on_received(PacketNumber(1), true, 2 * MS, false, DELAY);
        assert!(received.ack_due(2 * MS));

        // The acknowledgment reports 0..=1 with a delay of 3 ms since packet 1, scaled by 2^3.
        let ack = received.take_ack(5 * MS, 3).unwrap();
        assert_eq!(ack.ranges.first(), Some(&(0..2)));
        assert_eq!(ack.ranges.len(), 1);
        assert_eq!(ack.delay, 3000 >> 3);
        assert!(!received.ack_due(100 * MS));
    }

    #[test]
    fn reordering_and_eager_spaces_ack_at_once() {
        let mut received = ReceivedPackets::default();
        received.on_received(PacketNumber(0), true, Duration::ZERO, false, DELAY);
        received.take_ack(Duration::ZERO, 3);
        // Packet 2 skips 1.
        received.on_received(PacketNumber(2), true, MS, false, DELAY);
        assert!(received.ack_due(MS));
        assert_eq!(received.take_ack(MS, 3).unwrap().ranges, [2..3, 0..1]);

        let mut handshake = ReceivedPackets::default();
        handshake.on_received(PacketNumber(0), true, Duration::ZERO, true, DELAY);
        assert!(handshake.ack_due(Duration::ZERO));
        assert!(handshake.is_duplicate(PacketNumber(0)));
        assert!(!handshake.is_duplicate(PacketNumber(1)));
    }

    #[test]
    fn non_eliciting_packets_only_piggyback() {
        let mut received = ReceivedPackets::default();
        received.on_received(PacketNumber(0), false, Duration::ZERO, false, DELAY);
        assert!(!received.ack_due(DELAY * 4));
        assert!(received.can_piggyback());
    }
}
