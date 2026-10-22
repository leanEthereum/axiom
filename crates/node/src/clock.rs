//! Wall-clock time, injected so a simulation can replace it.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

/// A source of the current time.
///
/// The node never reads the system clock directly.
/// Tests and simulations drive time by hand instead.
pub trait Clock: fmt::Debug + Send + Sync + 'static {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

/// The operating system's real-time clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        // A clock set before 1970 reads as the epoch itself rather than failing.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// A clock that moves only when told to.
///
/// Clones share one reading, so a test keeps a clone and advances the node's time.
#[derive(Clone, Debug, Default)]
pub struct ManualClock {
    /// Milliseconds since the Unix epoch.
    now_ms: Arc<AtomicU64>,
}

impl ManualClock {
    /// A clock reading a fixed time.
    #[must_use]
    pub fn at(now_ms: u64) -> Self {
        Self {
            now_ms: Arc::new(AtomicU64::new(now_ms)),
        }
    }

    /// Moves the clock to a time.
    pub fn set(&self, now_ms: u64) {
        self.now_ms.store(now_ms, Ordering::Relaxed);
    }

    /// Moves the clock forward.
    pub fn advance(&self, by_ms: u64) {
        self.now_ms.fetch_add(by_ms, Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_of_a_manual_clock_share_one_reading() {
        // Fixture state: the node holds one clone, the test the other.
        let test = ManualClock::at(1_000);
        let node = test.clone();

        // Moving the test's clone moves the node's.
        test.advance(500);
        assert_eq!(node.now_ms(), 1_500);
        test.set(42);
        assert_eq!(node.now_ms(), 42);
    }

    #[test]
    fn the_system_clock_is_past_2020() {
        // 2020-01-01 in milliseconds; any real clock reads later.
        assert!(SystemClock.now_ms() > 1_577_836_800_000);
    }
}
