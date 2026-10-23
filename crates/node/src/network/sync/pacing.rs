//! Backfill pacing: past batches processed at quiet moments of the slot, so duties keep the CPU.

use std::{sync::Arc, time::Duration};

use axiom_types::SlotClock;
use tokio::time;

use crate::Clock;

/// Moments of each slot a backfill batch may start processing, as fractions of the slot.
///
/// A slot's block arrives in its first third, and its votes are due at one third.
/// Aggregates are due at two thirds.
/// Half, three fifths, and four fifths sit between those deadlines and the next slot's block.
/// On mainnet that is 6, 7.2, and 9.6 seconds into the slot.
const MOMENTS: [(u64, u64); 3] = [(1, 2), (3, 5), (4, 5)];

/// When the next backfill batch may run.
///
/// # Overview
///
/// Backfill is not needed to follow the chain or perform duties.
/// Verifying a batch costs thousands of signature checks, which compete with gossip and duties.
/// Paced, at most three batches run per slot, each at a moment the slot's deadlines leave quiet.
///
/// The operator may lift the pacing to fill the history as fast as the peers serve it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BackfillSchedule {
    /// Genesis and the slot length.
    slots: SlotClock,
}

impl BackfillSchedule {
    /// The moments of a slot clock.
    pub(crate) const fn new(slots: SlotClock) -> Self {
        Self { slots }
    }

    /// The first moment strictly after a time; before genesis, the first moment of slot zero.
    pub(crate) fn next(self, now_ms: u64) -> u64 {
        let slot = self.slots.slot_at(now_ms);
        let duration = self.slots.slot_duration_ms();
        let moment = |start: u64, (numerator, denominator): (u64, u64)| {
            start + duration / denominator * numerator
        };
        let start = self.slots.slot_start_ms(slot);
        MOMENTS
            .into_iter()
            .map(|fraction| moment(start, fraction))
            .find(|&at| at > now_ms)
            .unwrap_or_else(|| moment(self.slots.slot_start_ms(slot + 1), MOMENTS[0]))
    }
}

/// Holds each backfill batch until its moment.
#[derive(Debug, Clone)]
pub(crate) struct BackfillPacer {
    /// The wall clock.
    clock: Arc<dyn Clock>,
    /// The moments.
    schedule: BackfillSchedule,
}

impl BackfillPacer {
    /// A pacer on a wall clock.
    pub(crate) fn new(clock: Arc<dyn Clock>, slots: SlotClock) -> Self {
        Self {
            clock,
            schedule: BackfillSchedule::new(slots),
        }
    }

    /// Waits until the next moment a batch may run.
    pub(crate) async fn wait(&self) {
        let now = self.clock.now_ms();
        let at = self.schedule.next(now);
        time::sleep(Duration::from_millis(at.saturating_sub(now))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batches_run_at_half_three_fifths_and_four_fifths_of_a_slot() {
        // Fixture state: genesis at 1_000 ms and mainnet slots of 12_000 ms.
        // Slot 0 runs from 1_000 to 13_000, so its moments are 7_000, 8_200, and 10_600.
        let schedule = BackfillSchedule::new(SlotClock::new(1_000, 12_000));

        // From the slot start, the first moment is half way.
        assert_eq!(schedule.next(1_000), 7_000);

        // At a moment, the next one follows; the moment itself is past.
        assert_eq!(schedule.next(7_000), 8_200);
        assert_eq!(schedule.next(8_200), 10_600);

        // After the last moment, the next is half way through slot 1.
        assert_eq!(schedule.next(10_600), 19_000);
        assert_eq!(schedule.next(12_999), 19_000);

        // Before genesis, the first moment of slot zero.
        assert_eq!(schedule.next(0), 7_000);
    }
}
