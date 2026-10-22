//! The mapping between wall time and slots.

use crate::Slot;

/// Basis points in a whole, the unit slot deadlines are expressed in.
const BASIS_POINTS: u64 = 10_000;

/// Genesis and the slot length: everything needed to turn a time into a slot and back.
///
/// It never reads a clock.
/// Times are milliseconds since the Unix epoch, supplied by the caller.
///
/// See `get_current_slot` in the phase0 fork choice spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SlotClock {
    /// Start of the genesis slot.
    genesis_ms: u64,
    /// Length of every slot.
    slot_duration_ms: u64,
}

impl SlotClock {
    /// A clock for a chain that started at a time, with slots of a length.
    #[must_use]
    pub const fn new(genesis_ms: u64, slot_duration_ms: u64) -> Self {
        Self {
            genesis_ms,
            slot_duration_ms,
        }
    }

    /// Start of the genesis slot.
    #[must_use]
    pub const fn genesis_ms(self) -> u64 {
        self.genesis_ms
    }

    /// Length of every slot.
    #[must_use]
    pub const fn slot_duration_ms(self) -> u64 {
        self.slot_duration_ms
    }

    /// The slot a time falls in, with any time before genesis in the genesis slot.
    ///
    /// # Panics
    ///
    /// Panics when the slot length is zero.
    #[must_use]
    pub const fn slot_at(self, time_ms: u64) -> Slot {
        Slot(time_ms.saturating_sub(self.genesis_ms) / self.slot_duration_ms)
    }

    /// Start of a slot.
    #[must_use]
    pub const fn slot_start_ms(self, slot: Slot) -> u64 {
        self.genesis_ms + slot.0 * self.slot_duration_ms
    }

    /// Time elapsed since the start of the slot a time falls in.
    ///
    /// # Panics
    ///
    /// Panics when the slot length is zero, or the time is before genesis.
    #[must_use]
    pub const fn time_into_slot_ms(self, time_ms: u64) -> u64 {
        time_ms - self.slot_start_ms(self.slot_at(time_ms))
    }

    /// Length of a slot component given in basis points of the slot.
    ///
    /// Deadlines such as the attestation cutoff are configured this way.
    #[must_use]
    pub const fn component_ms(self, basis_points: u64) -> u64 {
        basis_points * self.slot_duration_ms / BASIS_POINTS
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn times_map_to_slots_and_back() {
        // Fixture state: genesis at 1_000_000 ms, 12-second slots.
        let clock = SlotClock::new(1_000_000, 12_000);

        // Slot 3 starts 36 seconds after genesis.
        assert_eq!(clock.slot_start_ms(Slot(3)), 1_036_000);

        // 5 seconds into slot 3 is still slot 3, 5_000 ms in.
        assert_eq!(clock.slot_at(1_041_000), Slot(3));
        assert_eq!(clock.time_into_slot_ms(1_041_000), 5_000);

        // A time before genesis falls in the genesis slot.
        assert_eq!(clock.slot_at(0), Slot::GENESIS);

        // A third of a slot, 3333 basis points, is 3_999 ms after truncation.
        assert_eq!(clock.component_ms(3333), 3_999);
    }

    proptest! {
        #[test]
        fn a_slot_start_falls_in_its_slot(
            genesis in 0_u64..1 << 40,
            duration in 1_u64..100_000,
            slot in 0_u64..1 << 20,
        ) {
            let clock = SlotClock::new(genesis, duration);
            let start = clock.slot_start_ms(Slot(slot));
            prop_assert_eq!(clock.slot_at(start), Slot(slot));
            prop_assert_eq!(clock.time_into_slot_ms(start), 0);
        }
    }
}
