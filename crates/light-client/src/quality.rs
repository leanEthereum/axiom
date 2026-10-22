//! The total order on light client updates that picks the best one.

use std::cmp::Reverse;

use axiom_types::{LightClientUpdate, Preset, Slot};

/// How good an update is, as a key whose natural order is the spec's preference.
///
/// # Overview
///
/// The spec ranks updates by a cascade of criteria, see `is_better_update`.
/// Each field below is one criterion, in cascade order.
/// Comparing two keys field by field reproduces the cascade exactly.
///
/// # Invariants
///
/// An update is better than another exactly when its key is greater.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one criterion of the spec's cascade"
)]
pub struct UpdateQuality {
    /// Whether two thirds of the committee signed.
    supermajority: bool,
    /// Signer count, compared only between two updates without a supermajority.
    participants_below_supermajority: usize,
    /// Whether it carries the next committee of its own period.
    relevant_sync_committee: bool,
    /// Whether it proves a finalized header.
    finality: bool,
    /// Whether the finalized header is in the attested period, compared only for finality updates.
    sync_committee_finality: bool,
    /// Signer count, the first tiebreaker.
    participants: usize,
    /// Attested slot, earlier preferred.
    attested_slot: Reverse<Slot>,
    /// Signature slot, earlier preferred.
    signature_slot: Reverse<Slot>,
}

impl UpdateQuality {
    /// The quality of an update.
    #[must_use]
    pub fn of<P: Preset>(update: &LightClientUpdate<P>) -> Self {
        let bits = &update.sync_aggregate.sync_committee_bits;
        let participants = bits.count_ones();
        // Threshold: participants * 3 >= committee * 2.
        let supermajority = participants * 3 >= bits.len() * 2;
        let period = |slot: Slot| slot.epoch::<P>().0 / P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let attested_slot = update.attested_header.beacon.slot;
        let finality = Self::is_finality_update(update);

        Self {
            supermajority,
            participants_below_supermajority: if supermajority { 0 } else { participants },
            relevant_sync_committee: Self::is_sync_committee_update(update)
                && period(attested_slot) == period(update.signature_slot),
            finality,
            sync_committee_finality: finality
                && period(update.finalized_header.beacon.slot) == period(attested_slot),
            participants,
            attested_slot: Reverse(attested_slot),
            signature_slot: Reverse(update.signature_slot),
        }
    }

    /// Whether an update carries a next sync committee.
    ///
    /// An all-zero branch marks its absence.
    #[must_use]
    pub fn is_sync_committee_update<P: Preset>(update: &LightClientUpdate<P>) -> bool {
        update
            .next_sync_committee_branch
            .iter()
            .any(|node| node.0 != [0; 32])
    }

    /// Whether an update proves a finalized header.
    #[must_use]
    pub fn is_finality_update<P: Preset>(update: &LightClientUpdate<P>) -> bool {
        update.finality_branch.iter().any(|node| node.0 != [0; 32])
    }
}
