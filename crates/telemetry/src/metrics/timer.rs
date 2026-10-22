//! A guard that times a scope into a histogram.

use std::time::Instant;

use crate::metrics::Histogram;

/// Measures wall time from its creation and records it, in seconds, when dropped.
///
/// 1. Creating the guard starts the clock.
/// 2. The timed work runs.
/// 3. The guard leaves scope, and the histogram observes the elapsed seconds.
#[derive(Debug)]
#[must_use = "a timer dropped at once records a duration near zero"]
pub struct Timer {
    /// The destination, taken once the duration is recorded or discarded.
    histogram: Option<Histogram>,

    /// When timing began.
    start: Instant,
}

impl Timer {
    /// Starts timing into a histogram.
    pub(crate) fn start(histogram: Histogram) -> Self {
        Self {
            histogram: Some(histogram),
            // A monotonic clock, so a wall clock step cannot yield a negative duration.
            start: Instant::now(),
        }
    }

    /// Seconds elapsed since timing began, without recording them.
    #[must_use]
    pub fn elapsed_seconds(&self) -> f64 {
        // The monotonic clock gives a duration that never runs backwards.
        self.start.elapsed().as_secs_f64()
    }

    /// Records the elapsed seconds now rather than at the end of the scope.
    pub fn observe(mut self) {
        // Taking the histogram leaves nothing for the drop to record twice.
        self.record();
    }

    /// Stops timing without recording, such as when the timed work failed.
    pub fn discard(mut self) {
        // With the histogram gone, the drop records nothing.
        self.histogram = None;
    }

    /// Records the elapsed seconds once, if still armed.
    fn record(&mut self) {
        // Only the first call finds the histogram.
        if let Some(histogram) = self.histogram.take() {
            histogram.observe(self.elapsed_seconds());
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        // A timer still armed at the end of its scope records that scope.
        self.record();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Buckets;

    #[test]
    fn records_once_unless_discarded() {
        let histogram = Histogram::new(Buckets::default());

        // A dropped timer records one observation.
        drop(histogram.start_timer());
        assert_eq!(histogram.snapshot().count, 1);

        // An explicit observation records once; the drop that follows records nothing.
        histogram.start_timer().observe();
        assert_eq!(histogram.snapshot().count, 2);

        // A discarded timer records nothing.
        histogram.start_timer().discard();
        assert_eq!(histogram.snapshot().count, 2);
    }
}
