//! When duties fall due: slot starts and the deadlines inside a slot.

use std::{sync::Arc, time::Duration};

use axiom_node::Clock;
use axiom_types::{Slot, SlotClock};
use tokio::time;

/// The wall clock read through the chain's slot schedule.
///
/// The clock is injected, so tests and simulations drive time by hand.
#[derive(Clone, Debug)]
pub struct SlotTimer {
    /// The wall clock.
    clock: Arc<dyn Clock>,
    /// Genesis and the slot length.
    slots: SlotClock,
}

impl SlotTimer {
    /// A timer over a clock and a slot schedule.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, slots: SlotClock) -> Self {
        Self { clock, slots }
    }

    /// The slot the wall clock is in.
    #[must_use]
    pub fn current_slot(&self) -> Slot {
        self.slots.slot_at(self.clock.now_ms())
    }

    /// The wall clock, in milliseconds since the Unix epoch.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// The moment a point of a slot is reached, in basis points of the slot.
    #[must_use]
    pub const fn deadline_ms(&self, slot: Slot, basis_points: u64) -> u64 {
        self.slots.slot_start_ms(slot) + self.slots.component_ms(basis_points)
    }

    /// Sleeps until a point of a slot, returning at once when it has passed.
    ///
    /// The sleep is re-measured against the clock when it ends, so a clock that jumps is caught up.
    pub async fn wait_until(&self, slot: Slot, basis_points: u64) {
        let deadline = self.deadline_ms(slot, basis_points);
        loop {
            let now = self.clock.now_ms();
            if now >= deadline {
                return;
            }
            time::sleep(Duration::from_millis(deadline - now)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_node::ManualClock;
    use tokio::runtime::Builder;

    use super::*;

    #[test]
    fn a_third_of_a_twelve_second_slot_is_four_seconds_in() {
        // Fixture state: genesis at 1_000_000 ms, 12-second slots, the clock in slot 2.
        let clock = ManualClock::at(1_000_000 + 25_000);
        let timer = SlotTimer::new(Arc::new(clock), SlotClock::new(1_000_000, 12_000));

        // Slot 2 starts at 24 s; 3333 basis points of it is 3_999 ms later.
        assert_eq!(timer.current_slot(), Slot(2));
        assert_eq!(timer.deadline_ms(Slot(2), 3333), 1_000_000 + 24_000 + 3_999);
    }

    #[test]
    fn a_passed_deadline_returns_at_once() {
        Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                // The clock reads slot 5; waiting for the start of slot 1 returns immediately.
                let clock = ManualClock::at(60_000);
                let timer = SlotTimer::new(Arc::new(clock), SlotClock::new(0, 12_000));
                timer.wait_until(Slot(1), 0).await;
            });
    }
}
