//! The committees this node's validators aggregate, which decide which subnet votes are pooled.

use std::collections::BTreeSet;

use axiom_types::{CommitteeIndex, Slot};

/// Slots an aggregation duty is kept past its own.
///
/// An aggregator publishes two thirds into its slot.
/// Votes of the slot still arrive in the next one, so two slots cover every late vote it can use.
const KEPT_SLOTS: u64 = 2;

/// Committees a local validator aggregates, by slot.
///
/// # Overview
///
/// A vote received alone on a subnet serves two readers:
///
/// - the fork choice, which counts every valid vote,
/// - the pool, which aggregates votes for a local aggregator.
///
/// Pooling every subnet vote costs a signature aggregation per vote.
/// Only a committee some local validator aggregates needs its votes pooled.
/// Its aggregate reaches the pool anyway, on the aggregate topic.
///
/// In one slot, each committee has its own subnet.
/// So a committee and a slot name exactly the subnet the duty covers.
/// See `compute_subnet_for_attestation` in the phase0 validator spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AggregationDuties {
    /// Duties by slot, then committee, so expired ones leave from the front.
    duties: BTreeSet<(Slot, CommitteeIndex)>,
}

impl AggregationDuties {
    /// Records that a local validator aggregates a committee, dropping duties long past.
    pub(crate) fn insert(&mut self, slot: Slot, committee: CommitteeIndex, current: Slot) {
        self.prune(current);
        if slot.0.saturating_add(KEPT_SLOTS) >= current.0 {
            self.duties.insert((slot, committee));
        }
    }

    /// Whether a local validator aggregates a committee at a slot.
    pub(crate) fn contains(&self, slot: Slot, committee: CommitteeIndex) -> bool {
        self.duties.contains(&(slot, committee))
    }

    /// Drops duties more than the kept slots behind the current slot.
    fn prune(&mut self, current: Slot) {
        let oldest = Slot(current.0.saturating_sub(KEPT_SLOTS));
        self.duties = self.duties.split_off(&(oldest, CommitteeIndex(0)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duties_cover_their_slot_and_two_more() {
        // Fixture state: at slot 10, a local validator aggregates committee 3 of slot 10.
        let mut duties = AggregationDuties::default();
        duties.insert(Slot(10), CommitteeIndex(3), Slot(10));

        // The duty names one committee at one slot.
        assert!(duties.contains(Slot(10), CommitteeIndex(3)));
        assert!(!duties.contains(Slot(10), CommitteeIndex(2)));
        assert!(!duties.contains(Slot(11), CommitteeIndex(3)));

        // At slot 12 it is still kept; any insert at slot 13 drops it.
        duties.insert(Slot(12), CommitteeIndex(0), Slot(12));
        assert!(duties.contains(Slot(10), CommitteeIndex(3)));
        duties.insert(Slot(13), CommitteeIndex(0), Slot(13));
        assert!(!duties.contains(Slot(10), CommitteeIndex(3)));
        assert!(duties.contains(Slot(12), CommitteeIndex(0)));
    }

    #[test]
    fn a_duty_already_past_is_not_kept() {
        // At slot 20, a duty of slot 17 is three slots old, one past the window.
        let mut duties = AggregationDuties::default();
        duties.insert(Slot(17), CommitteeIndex(1), Slot(20));
        assert_eq!(duties, AggregationDuties::default());

        // A duty of slot 18 is two slots old, the last one kept.
        duties.insert(Slot(18), CommitteeIndex(1), Slot(20));
        assert!(duties.contains(Slot(18), CommitteeIndex(1)));
    }
}
