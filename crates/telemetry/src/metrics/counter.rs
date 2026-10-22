//! A monotonic counter.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// A count that only goes up, such as reorgs seen or bytes written.
///
/// Clones share one value, so a clone on another thread updates the same series.
#[derive(Clone, Debug, Default)]
pub struct Counter {
    /// The shared count.
    value: Arc<AtomicU64>,
}

impl Counter {
    /// A counter at zero, not yet in any registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one.
    pub fn inc(&self) {
        // One is the common step: one reorg, one message.
        self.inc_by(1);
    }

    /// Adds an amount.
    ///
    /// The count wraps past the largest value, which no real workload reaches.
    pub fn inc_by(&self, amount: u64) {
        // Relaxed suffices: no other memory is published through this value.
        self.value.fetch_add(amount, Ordering::Relaxed);
    }

    /// The current count.
    #[must_use]
    pub fn get(&self) -> u64 {
        // A scrape needs a recent value, not one ordered with other writes.
        self.value.load(Ordering::Relaxed)
    }
}
