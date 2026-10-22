//! An inclusive range of slots, and the committee weight it holds.

use axiom_types::{Gwei, Preset, Slot};

/// Per mille added to a committee weight estimate across an epoch boundary.
///
/// It keeps the rule safe with high probability when the range covers no full epoch.
/// See the fast confirmation spec's constants.
const COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR: u64 = 5;

/// The slots from a first one through a last one, empty when the last comes first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SlotRange {
    /// The first slot.
    start: Slot,
    /// The last slot, included.
    end: Slot,
}

impl SlotRange {
    /// The slots from a first one through a last one.
    pub(super) const fn new(start: Slot, end: Slot) -> Self {
        Self { start, end }
    }

    /// Whether the range holds no slot.
    pub(super) fn is_empty(self) -> bool {
        self.start > self.end
    }

    /// The slots of the range, in order.
    pub(super) fn slots(self) -> impl Iterator<Item = Slot> {
        (self.start.0..=self.end.0).map(Slot)
    }

    /// Estimated committee weight of the range, out of a total active balance.
    ///
    /// # Algorithm
    ///
    /// A range covering a full epoch holds the whole validator set.
    /// A range within one epoch holds one committee per slot.
    ///
    /// A range straddling a boundary is pro-rated.
    /// The start epoch's slots count only for the share of validators not yet seen in the end epoch.
    /// The result is then raised by half a percent to stay safe with high probability.
    ///
    /// See `estimate_committee_weight_between_slots` in the phase0 fast confirmation spec.
    pub(super) fn committee_weight<P: Preset>(self, total: Gwei) -> Gwei {
        let Self { start, end } = self;
        if self.is_empty() {
            return Gwei::ZERO;
        }
        let full_epoch_covered =
            (start + (P::SLOTS_PER_EPOCH - 1)).epoch::<P>() < (end + 1).epoch::<P>();
        if full_epoch_covered {
            return total;
        }
        let committee_weight = total / P::SLOTS_PER_EPOCH;
        let (start_epoch, end_epoch) = (start.epoch::<P>(), end.epoch::<P>());
        if start_epoch == end_epoch {
            return committee_weight * (end - start + 1);
        }

        let slots_in_end_epoch = end.index_in_epoch::<P>() + 1;
        let remaining_in_end_epoch = P::SLOTS_PER_EPOCH - slots_in_end_epoch;
        let slots_in_start_epoch = P::SLOTS_PER_EPOCH - start.index_in_epoch::<P>();
        let start_weight = committee_weight * slots_in_start_epoch;
        let end_weight = committee_weight * slots_in_end_epoch;
        let start_pro_rated = start_weight / P::SLOTS_PER_EPOCH * remaining_in_end_epoch;

        // Round up to whole thousandths, then add the adjustment factor.
        let estimate = start_pro_rated + end_weight;
        Gwei(estimate.0.div_ceil(1000) * (1000 + COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR))
    }
}
