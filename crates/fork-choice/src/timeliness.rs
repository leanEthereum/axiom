//! Whether a block arrived in time for the votes of its own slot.

use axiom_types::{Slot, SlotClock};

/// When a block arrived, measured against the two deadlines of its slot.
///
/// Gloas records the payload timeliness committee's deadline beside the attesters'.
/// Earlier forks only read the attesters' one.
/// See `record_block_timeliness` in the phase0 and Gloas fork choice specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeliness {
    /// Whether the block arrived in its slot, before the attestation deadline.
    pub attestation: bool,
    /// Whether the block arrived in its slot, before the payload attestation deadline.
    pub ptc: bool,
}

impl Timeliness {
    /// The anchor counts as timely for both deadlines.
    ///
    /// See `get_forkchoice_store` in the Gloas fork choice spec.
    pub const ANCHOR: Self = Self {
        attestation: true,
        ptc: true,
    };

    /// The timeliness of a block of a slot, arriving at a time.
    ///
    /// Each deadline is given in basis points of the slot.
    #[must_use]
    pub const fn of(
        clock: SlotClock,
        time_ms: u64,
        slot: Slot,
        attestation_due_bps: u64,
        ptc_due_bps: u64,
    ) -> Self {
        let in_slot = clock.slot_at(time_ms).0 == slot.0;
        let into_slot = clock.time_into_slot_ms(time_ms);
        Self {
            attestation: in_slot && into_slot < clock.component_ms(attestation_due_bps),
            ptc: in_slot && into_slot < clock.component_ms(ptc_due_bps),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_deadline_is_judged_on_its_own() {
        // Fixture state: 12 second slots from time zero, deadlines at 25% and 75% of a slot.
        let clock = SlotClock::new(0, 12_000);
        let at = |time_ms| Timeliness::of(clock, time_ms, Slot(1), 2500, 7500);

        // 13 s is 1 s into slot 1: before both deadlines, 3 s and 9 s in.
        assert_eq!(
            at(13_000),
            Timeliness {
                attestation: true,
                ptc: true
            }
        );
        // 17 s is 5 s in: past the attesters' deadline, before the committee's.
        assert_eq!(
            at(17_000),
            Timeliness {
                attestation: false,
                ptc: true
            }
        );
        // 25 s falls in slot 2, so the block of slot 1 is late for both.
        assert_eq!(
            at(25_000),
            Timeliness {
                attestation: false,
                ptc: false
            }
        );
    }
}
