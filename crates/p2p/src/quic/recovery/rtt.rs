//! Round-trip time estimation, per RFC 9002, section 5.

use std::time::Duration;

/// The RTT assumed before any sample, per RFC 9002, section 6.2.2.
pub(crate) const INITIAL_RTT: Duration = Duration::from_millis(333);

/// The timer granularity, per RFC 9002, section 6.1.2.
pub(crate) const GRANULARITY: Duration = Duration::from_millis(1);

/// The smoothed round-trip time and its variation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RttEstimator {
    /// The most recent sample.
    latest: Duration,
    /// The exponentially weighted mean.
    smoothed: Duration,
    /// The mean deviation.
    variance: Duration,
    /// The smallest sample seen, ignoring ack delay.
    min: Duration,
    /// Whether any sample has arrived.
    sampled: bool,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            latest: INITIAL_RTT,
            smoothed: INITIAL_RTT,
            variance: INITIAL_RTT / 2,
            min: Duration::ZERO,
            sampled: false,
        }
    }
}

impl RttEstimator {
    /// The most recent sample.
    pub(crate) const fn latest(&self) -> Duration {
        self.latest
    }

    /// The smoothed RTT.
    pub(crate) const fn smoothed(&self) -> Duration {
        self.smoothed
    }

    /// The RTT variation.
    pub(crate) const fn variance(&self) -> Duration {
        self.variance
    }

    /// Whether any sample has arrived.
    pub(crate) const fn has_sample(&self) -> bool {
        self.sampled
    }

    /// Takes a sample, discounting the peer's reported ack delay when that keeps it above the minimum.
    ///
    /// # Arguments
    ///
    /// - `latest`: the time from sending the largest newly acknowledged packet to its acknowledgment.
    /// - `ack_delay`: the delay the peer reports, already capped at its max_ack_delay once confirmed.
    ///
    /// # Algorithm
    ///
    /// RFC 9002, section 5.3:
    ///
    /// ```text
    /// adjusted = latest - ack_delay, if that stays at or above min_rtt
    /// rttvar   = 3/4 rttvar + 1/4 |smoothed - adjusted|
    /// smoothed = 7/8 smoothed + 1/8 adjusted
    /// ```
    pub(crate) fn update(&mut self, latest: Duration, ack_delay: Duration) {
        self.latest = latest;
        if !self.sampled {
            self.sampled = true;
            self.min = latest;
            self.smoothed = latest;
            self.variance = latest / 2;
            return;
        }
        self.min = self.min.min(latest);
        let adjusted = if latest >= self.min + ack_delay {
            latest - ack_delay
        } else {
            latest
        };
        let deviation = self.smoothed.abs_diff(adjusted);
        self.variance = (self.variance * 3 + deviation) / 4;
        self.smoothed = (self.smoothed * 7 + adjusted) / 8;
    }

    /// The probe timeout before backoff, without the peer's ack delay.
    ///
    /// ```text
    /// pto = smoothed_rtt + max(4 * rttvar, granularity)
    /// ```
    pub(crate) fn pto_base(&self) -> Duration {
        self.smoothed + (self.variance * 4).max(GRANULARITY)
    }

    /// The time-threshold loss delay: 9/8 of the larger of the latest and smoothed RTTs.
    pub(crate) fn loss_delay(&self) -> Duration {
        (self.latest.max(self.smoothed) * 9 / 8).max(GRANULARITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn first_sample_seeds_the_estimate() {
        let mut rtt = RttEstimator::default();
        // Before any sample: 333 ms, variance 166.5 ms, PTO 333 + 666 = 999 ms.
        assert_eq!(rtt.pto_base(), Duration::from_micros(999_000));
        rtt.update(100 * MS, 20 * MS);
        // The first sample ignores the ack delay.
        assert_eq!((rtt.smoothed(), rtt.variance()), (100 * MS, 50 * MS));
        assert_eq!(rtt.pto_base(), 300 * MS);
    }

    #[test]
    fn later_samples_subtract_ack_delay_above_the_minimum() {
        let mut rtt = RttEstimator::default();
        rtt.update(100 * MS, Duration::ZERO);
        // 140 ms with 20 ms of delay: adjusted 120, deviation 20.
        rtt.update(140 * MS, 20 * MS);
        assert_eq!(rtt.variance(), Duration::from_micros(42_500));
        assert_eq!(rtt.smoothed(), Duration::from_micros(102_500));

        // 105 ms with 20 ms of delay would fall below the 100 ms minimum: no adjustment.
        rtt.update(105 * MS, 20 * MS);
        assert_eq!(rtt.latest(), 105 * MS);
        assert_eq!(
            rtt.smoothed(),
            Duration::from_micros(102_812) + Duration::from_nanos(500)
        );
    }

    #[test]
    fn loss_delay_is_nine_eighths_and_at_least_the_granularity() {
        let mut rtt = RttEstimator::default();
        rtt.update(80 * MS, Duration::ZERO);
        assert_eq!(rtt.loss_delay(), 90 * MS);
        let mut tiny = RttEstimator::default();
        tiny.update(Duration::from_micros(100), Duration::ZERO);
        assert_eq!(tiny.loss_delay(), GRANULARITY);
    }
}
