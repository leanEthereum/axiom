//! A distribution of observations over fixed buckets.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use crate::metrics::{Buckets, Timer};

/// Counts of observations at or below each bucket bound, with their sum.
///
/// # Overview
///
/// Each observation lands in exactly one slot: the first bound at or above it.
/// The exposition accumulates the slots, as Prometheus expects.
///
/// ```text
///     bounds        0.1    0.5    1.0    +Inf
///     observe 0.3          x
///     observe 0.7                 x
///     observe 4.0                        x
///     slots         0      1      1      1
///     cumulative    0      1      2      3      count = 3, sum = 5.0
/// ```
///
/// Clones share one set of slots.
#[derive(Clone, Debug)]
pub struct Histogram {
    /// The shared slots and sum.
    core: Arc<Core>,
}

/// The state every clone of a histogram shares.
#[derive(Debug)]
struct Core {
    /// The finite bucket bounds.
    buckets: Buckets,

    /// One count per finite bound, then one for the infinite bucket.
    slots: Box<[AtomicU64]>,

    /// The sum of every observation, as the bits of a float.
    sum: AtomicU64,
}

impl Histogram {
    /// An empty histogram over these buckets, not yet in any registry.
    #[must_use]
    pub fn new(buckets: Buckets) -> Self {
        // One slot per finite bound plus the infinite bucket.
        let slots = (0..=buckets.bounds().len())
            .map(|_| AtomicU64::new(0))
            .collect();
        Self {
            core: Arc::new(Core {
                buckets,
                slots,
                sum: AtomicU64::new(0.0_f64.to_bits()),
            }),
        }
    }

    /// Records one observation.
    ///
    /// NaN lands in the infinite bucket and turns the sum into NaN, as in the Go client.
    pub fn observe(&self, value: f64) {
        let bounds = self.core.buckets.bounds();
        // The first bound at or above the value; past the end means the infinite bucket.
        let slot = if value.is_nan() {
            bounds.len()
        } else {
            bounds.partition_point(|bound| *bound < value)
        };
        self.core.slots[slot].fetch_add(1, Ordering::Relaxed);

        // Atomics have no float add, so swap in the new sum until no other thread intervenes.
        // The closure always returns a value, so the update cannot fail.
        let _ = self
            .core
            .sum
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |bits| {
                Some((f64::from_bits(bits) + value).to_bits())
            });
    }

    /// Starts a timer that records elapsed seconds here when dropped.
    pub fn start_timer(&self) -> Timer {
        // The timer holds its own handle, so it may outlive this borrow.
        Timer::start(self.clone())
    }

    /// A consistent view of the counts and the sum.
    ///
    /// The total is the sum of the slots, so the infinite bucket always equals it.
    /// A concurrent observation may be counted while its sum is not yet added.
    #[must_use]
    pub fn snapshot(&self) -> HistogramSnapshot {
        let bounds = self.core.buckets.bounds();
        let mut total = 0_u64;
        // Accumulate slots into the cumulative counts the exposition format expects.
        let buckets = self
            .core
            .slots
            .iter()
            .enumerate()
            .map(|(index, slot)| {
                total = total.wrapping_add(slot.load(Ordering::Relaxed));
                // The slot past the finite bounds is the infinite bucket.
                let bound = bounds.get(index).copied().unwrap_or(f64::INFINITY);
                (bound, total)
            })
            .collect();
        HistogramSnapshot {
            buckets,
            sum: f64::from_bits(self.core.sum.load(Ordering::Relaxed)),
            count: total,
        }
    }
}

/// The state of a histogram at one instant.
#[derive(Clone, Debug, PartialEq)]
pub struct HistogramSnapshot {
    /// Each upper bound with the count at or below it, ending with infinity.
    pub buckets: Vec<(f64, u64)>,

    /// The sum of every observation.
    pub sum: f64,

    /// The number of observations.
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observations_land_in_the_first_bound_at_or_above() {
        // Fixture state: bounds 0.1, 0.5, 1.0, then the infinite bucket.
        // Observations: 0.25, 0.5, 4.0.
        let buckets = Buckets::new(&[0.1, 0.5, 1.0]).expect("valid bounds");
        let histogram = Histogram::new(buckets);

        // 0.5 sits on a bound and counts as at or below it.
        // 4.0 exceeds every finite bound.
        //
        //     slots       0.1:0  0.5:2  1.0:0  +Inf:1
        //     cumulative  0      2      2      3
        // The values are dyadic, so the sum 4.75 is exact.
        histogram.observe(0.25);
        histogram.observe(0.5);
        histogram.observe(4.0);
        assert_eq!(
            histogram.snapshot(),
            HistogramSnapshot {
                buckets: vec![(0.1, 0), (0.5, 2), (1.0, 2), (f64::INFINITY, 3)],
                sum: 4.75,
                count: 3,
            }
        );
    }

    #[test]
    fn nan_goes_to_the_infinite_bucket() {
        // One finite bound at 1.0.
        let histogram = Histogram::new(Buckets::new(&[1.0]).expect("valid bounds"));

        // NaN compares false with every bound, so it is placed past them all.
        histogram.observe(f64::NAN);
        let snapshot = histogram.snapshot();
        assert_eq!(snapshot.buckets, vec![(1.0, 0), (f64::INFINITY, 1)]);
        assert!(snapshot.sum.is_nan());
    }
}
