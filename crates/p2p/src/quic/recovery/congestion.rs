//! NewReno congestion control, per RFC 9002, section 7.
//!
//! # Overview
//!
//! The window caps the bytes in flight.
//!
//! 1. Slow start grows it by every acknowledged byte, doubling it each round trip.
//! 2. A loss halves it and enters recovery for packets sent before the loss was seen.
//! 3. Above the slow start threshold, it grows by one datagram per window acknowledged.
//! 4. Persistent congestion collapses it to the minimum.
//!
//! Without pacing, a sender may emit the whole window at once.
//! Bursts are therefore bounded by the window itself, as RFC 9002, section 7.7, permits.

use std::time::Duration;

/// The factor a loss scales the window by, per RFC 9002, section 7.3.2.
const LOSS_REDUCTION_DIVISOR: u64 = 2;

/// The NewReno controller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewReno {
    /// The largest datagram this side sends.
    max_datagram: u64,
    /// Bytes allowed in flight.
    window: u64,
    /// The window at which slow start ends.
    threshold: u64,
    /// Bytes sent and neither acknowledged nor lost.
    in_flight: u64,
    /// When the current recovery period began.
    recovery_start: Option<Duration>,
    /// Acknowledged bytes not yet added in congestion avoidance.
    avoidance_credit: u64,
}

impl NewReno {
    /// A controller with the initial window of RFC 9002, section 7.2.
    ///
    /// ```text
    /// initial window = min(10 * max_datagram, max(14720, 2 * max_datagram))
    /// ```
    pub(crate) fn new(max_datagram: u64) -> Self {
        Self {
            max_datagram,
            window: (10 * max_datagram).min(14_720.max(2 * max_datagram)),
            threshold: u64::MAX,
            in_flight: 0,
            recovery_start: None,
            avoidance_credit: 0,
        }
    }

    /// The smallest window, two datagrams.
    const fn min_window(&self) -> u64 {
        2 * self.max_datagram
    }

    /// The congestion window.
    #[cfg(test)]
    pub(crate) const fn window(&self) -> u64 {
        self.window
    }

    /// Bytes in flight.
    #[cfg(test)]
    pub(crate) const fn in_flight(&self) -> u64 {
        self.in_flight
    }

    /// Bytes that may still be sent before the window is full.
    pub(crate) const fn available(&self) -> u64 {
        self.window.saturating_sub(self.in_flight)
    }

    /// Counts a packet sent in flight.
    pub(crate) const fn on_sent(&mut self, bytes: u64) {
        self.in_flight += bytes;
    }

    /// Removes a packet from flight without a congestion signal, as when its keys are discarded.
    pub(crate) const fn on_discarded(&mut self, bytes: u64) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
    }

    /// Grows the window for an acknowledged packet.
    ///
    /// # Arguments
    ///
    /// - `bytes`: the packet's size.
    /// - `sent_at`: when it was sent; packets sent during recovery do not grow the window.
    pub(crate) fn on_acked(&mut self, bytes: u64, sent_at: Duration) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
        if self.recovery_start.is_some_and(|start| sent_at <= start) {
            return;
        }
        if self.window < self.threshold {
            self.window += bytes;
            return;
        }
        // Congestion avoidance: one datagram per window of acknowledged bytes.
        self.avoidance_credit += bytes;
        if self.avoidance_credit >= self.window {
            self.avoidance_credit -= self.window;
            self.window += self.max_datagram;
        }
    }

    /// Removes a lost packet from flight.
    pub(crate) const fn on_lost(&mut self, bytes: u64) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
    }

    /// Reacts to a loss: halves the window unless the lost packet predates the current recovery.
    pub(crate) fn on_congestion(&mut self, sent_at: Duration, now: Duration) {
        if self.recovery_start.is_some_and(|start| sent_at <= start) {
            return;
        }
        self.recovery_start = Some(now);
        self.window = (self.window / LOSS_REDUCTION_DIVISOR).max(self.min_window());
        self.threshold = self.window;
        self.avoidance_credit = 0;
    }

    /// Collapses the window after persistent congestion, per RFC 9002, section 7.6.2.
    pub(crate) const fn on_persistent_congestion(&mut self) {
        self.window = self.min_window();
        self.recovery_start = None;
        self.avoidance_credit = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn initial_window() {
        // 1200-byte datagrams: min(12000, max(14720, 2400)) = 12000.
        assert_eq!(NewReno::new(1200).window(), 12_000);
        // 1500-byte datagrams: min(15000, 14720) = 14720.
        assert_eq!(NewReno::new(1500).window(), 14_720);
    }

    #[test]
    fn slow_start_loss_and_avoidance() {
        let mut cc = NewReno::new(1200);
        cc.on_sent(2400);
        // Slow start: each acknowledged byte grows the window.
        cc.on_acked(1200, 10 * MS);
        assert_eq!(cc.window(), 13_200);
        assert_eq!(cc.in_flight(), 1200);

        // A loss at 50 ms of a packet sent at 20 ms halves the window to 6600.
        cc.on_lost(1200);
        cc.on_congestion(20 * MS, 50 * MS);
        assert_eq!(cc.window(), 6600);

        // A second loss from before the recovery began changes nothing.
        cc.on_congestion(40 * MS, 60 * MS);
        assert_eq!(cc.window(), 6600);

        // Packets sent during recovery do not grow the window.
        cc.on_acked(1200, 45 * MS);
        assert_eq!(cc.window(), 6600);

        // After recovery, avoidance adds 1200 once 6600 bytes are acknowledged.
        for _ in 0..5 {
            cc.on_acked(1200, 70 * MS);
        }
        assert_eq!(cc.window(), 6600);
        cc.on_acked(1200, 70 * MS);
        assert_eq!(cc.window(), 7800);
    }

    #[test]
    fn floors_at_two_datagrams() {
        let mut cc = NewReno::new(1200);
        for step in 1..10 {
            cc.on_congestion(step * 100 * MS, step * 100 * MS + MS);
        }
        assert_eq!(cc.window(), 2400);
        cc.on_persistent_congestion();
        assert_eq!(cc.window(), 2400);
        assert_eq!(cc.available(), 2400);
    }
}
