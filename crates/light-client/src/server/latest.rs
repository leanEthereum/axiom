//! The latest finality or optimistic update a full node serves, with the slots that rank it.

use axiom_types::{Preset, Slot};

use crate::{Header, UpdateData};

/// The slots and participation of an update, read once when it is offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Summary {
    /// Slot of the attested header.
    pub(super) attested: Slot,
    /// Slot of the block carrying the signature.
    pub(super) signature: Slot,
    /// Slot of the finalized header, zero when it is empty.
    pub(super) finalized: Slot,
    /// Whether more than two thirds of the committee signed.
    pub(super) supermajority: bool,
}

impl Summary {
    /// The summary of an update's fields.
    pub(super) fn of<P: Preset, H: Header<P>>(update: &UpdateData<H, P>) -> Self {
        let bits = &update.sync_aggregate.sync_committee_bits;
        Self {
            attested: update.attested_header.beacon().slot,
            signature: update.signature_slot,
            finalized: update.finalized_header.beacon().slot,
            // Threshold: participants * 3 > committee * 2, the gossip rule's strict supermajority.
            supermajority: bits.count_ones() * 3 > bits.len() * 2,
        }
    }

    /// The order of latest updates: the higher attested slot, then the higher signature slot.
    ///
    /// See `create_light_client_finality_update` in the Altair light client full node spec.
    pub(super) const fn recency(self) -> (Slot, Slot) {
        (self.attested, self.signature)
    }
}

/// A latest update, kept with its summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Latest<T> {
    /// The update as served.
    pub(super) update: T,
    /// Its slots and participation.
    pub(super) summary: Summary,
}

impl<T> Latest<T> {
    /// Whether an update with a summary is more recent than this one.
    pub(super) fn is_older_than(&self, summary: Summary) -> bool {
        summary.recency() > self.summary.recency()
    }
}
