//! A value that moves both ways.

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

/// A signed integer that is set or adjusted, such as the head slot or the peer count.
///
/// Clones share one value.
#[derive(Clone, Debug, Default)]
pub struct Gauge {
    /// The shared value.
    value: Arc<AtomicI64>,
}

impl Gauge {
    /// A gauge at zero, not yet in any registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the value.
    pub fn set(&self, value: i64) {
        // Relaxed suffices: the gauge publishes no other memory.
        self.value.store(value, Ordering::Relaxed);
    }

    /// Adds one.
    pub fn inc(&self) {
        // Peers and tasks come and go one at a time.
        self.add(1);
    }

    /// Subtracts one.
    pub fn dec(&self) {
        // The mirror of a single increment.
        self.sub(1);
    }

    /// Adds an amount, wrapping at the bounds of the type.
    pub fn add(&self, amount: i64) {
        // An atomic add keeps concurrent adjustments from losing updates.
        self.value.fetch_add(amount, Ordering::Relaxed);
    }

    /// Subtracts an amount, wrapping at the bounds of the type.
    pub fn sub(&self, amount: i64) {
        // An atomic subtract, for the same reason as the add.
        self.value.fetch_sub(amount, Ordering::Relaxed);
    }

    /// The current value.
    #[must_use]
    pub fn get(&self) -> i64 {
        // A scrape needs a recent value, not one ordered with other writes.
        self.value.load(Ordering::Relaxed)
    }
}
