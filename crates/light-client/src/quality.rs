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
        let attested_slot = update.attested_header.beacon.slot;
        let finality = update.is_finality_update();

        Self {
            supermajority,
            participants_below_supermajority: if supermajority { 0 } else { participants },
            relevant_sync_committee: update.is_sync_committee_update()
                && attested_slot.sync_committee_period::<P>()
                    == update.signature_slot.sync_committee_period::<P>(),
            finality,
            sync_committee_finality: finality
                && update
                    .finalized_header
                    .beacon
                    .slot
                    .sync_committee_period::<P>()
                    == attested_slot.sync_committee_period::<P>(),
            participants,
            attested_slot: Reverse(attested_slot),
            signature_slot: Reverse(update.signature_slot),
        }
    }
}
