//! Light client data with its fields laid bare, the same for every fork.

use axiom_types::{
    Bytes32, Preset, Slot,
    altair::{SyncAggregate, SyncCommittee},
};

/// The fields of a bootstrap, over any header format.
///
/// # Overview
///
/// Each fork defines its own bootstrap container, differing only in header and branch types.
/// The store's rules read the fields, so they work on this one shape.
/// A fork converts its container to and from it, padding branches to the fork's length.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootstrapData<H, P: Preset> {
    /// The trusted block.
    pub header: H,
    /// Sync committee of the block's period.
    pub current_sync_committee: SyncCommittee<P>,
    /// Proof of that committee against the state root.
    pub current_sync_committee_branch: Vec<Bytes32>,
}

/// The fields of an update, over any header format.
///
/// Finality and optimistic updates take this shape too, with the missing fields empty.
/// An all-zero branch marks a proof the update does not carry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateData<H, P: Preset> {
    /// Header the sync committee signed.
    pub attested_header: H,
    /// Sync committee of the next period.
    pub next_sync_committee: SyncCommittee<P>,
    /// Proof of the next committee against the attested state.
    pub next_sync_committee_branch: Vec<Bytes32>,
    /// Header finalized by the attested state.
    pub finalized_header: H,
    /// Proof of the finalized root against the attested state.
    pub finality_branch: Vec<Bytes32>,
    /// Sync committee signature over the attested header.
    pub sync_aggregate: SyncAggregate<P>,
    /// Slot of the block carrying the signature.
    pub signature_slot: Slot,
}

impl<H, P: Preset> BootstrapData<H, P> {
    /// The same bootstrap with its header converted.
    pub fn map<G>(self, f: impl FnOnce(H) -> G) -> BootstrapData<G, P> {
        BootstrapData {
            header: f(self.header),
            current_sync_committee: self.current_sync_committee,
            current_sync_committee_branch: self.current_sync_committee_branch,
        }
    }

    /// The same bootstrap with its header converted, when it converts.
    ///
    /// # Errors
    ///
    /// Fails when the conversion fails.
    pub fn try_map<G, E>(
        self,
        f: impl FnOnce(H) -> Result<G, E>,
    ) -> Result<BootstrapData<G, P>, E> {
        Ok(BootstrapData {
            header: f(self.header)?,
            current_sync_committee: self.current_sync_committee,
            current_sync_committee_branch: self.current_sync_committee_branch,
        })
    }
}

impl<H, P: Preset> UpdateData<H, P> {
    /// Whether the update carries a next sync committee.
    ///
    /// See `is_sync_committee_update` in the Altair light client sync protocol.
    #[must_use]
    pub fn is_sync_committee_update(&self) -> bool {
        self.next_sync_committee_branch
            .iter()
            .any(|node| *node != Bytes32::ZERO)
    }

    /// Whether the update proves a finalized header.
    ///
    /// See `is_finality_update` in the Altair light client sync protocol.
    #[must_use]
    pub fn is_finality_update(&self) -> bool {
        self.finality_branch
            .iter()
            .any(|node| *node != Bytes32::ZERO)
    }

    /// Members of the sync committee that signed.
    #[must_use]
    pub fn participants(&self) -> usize {
        self.sync_aggregate.sync_committee_bits.count_ones()
    }

    /// The same update with both headers converted.
    pub fn map<G>(self, mut f: impl FnMut(H) -> G) -> UpdateData<G, P> {
        UpdateData {
            attested_header: f(self.attested_header),
            next_sync_committee: self.next_sync_committee,
            next_sync_committee_branch: self.next_sync_committee_branch,
            finalized_header: f(self.finalized_header),
            finality_branch: self.finality_branch,
            sync_aggregate: self.sync_aggregate,
            signature_slot: self.signature_slot,
        }
    }

    /// The same update with both headers converted, when both convert.
    ///
    /// # Errors
    ///
    /// Fails when either conversion fails.
    pub fn try_map<G, E>(
        self,
        mut f: impl FnMut(H) -> Result<G, E>,
    ) -> Result<UpdateData<G, P>, E> {
        Ok(UpdateData {
            attested_header: f(self.attested_header)?,
            next_sync_committee: self.next_sync_committee,
            next_sync_committee_branch: self.next_sync_committee_branch,
            finalized_header: f(self.finalized_header)?,
            finality_branch: self.finality_branch,
            sync_aggregate: self.sync_aggregate,
            signature_slot: self.signature_slot,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;

    use super::*;

    #[test]
    fn a_proof_is_present_when_any_node_is_nonzero() {
        // Fixture state: an update with all-zero branches carries no proof at all.
        let mut update = UpdateData::<(), Minimal> {
            next_sync_committee_branch: vec![Bytes32::ZERO; 5],
            finality_branch: vec![Bytes32::ZERO; 6],
            ..UpdateData::default()
        };
        assert!(!update.is_sync_committee_update());
        assert!(!update.is_finality_update());

        // Mutation: one nonzero node at the top of the finality branch.
        update.finality_branch[5] = Bytes32([1; 32]);
        assert!(update.is_finality_update());
        assert!(!update.is_sync_committee_update());
    }
}
