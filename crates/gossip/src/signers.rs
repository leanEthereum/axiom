//! The validators a state expects to sign gossip, and the checks of their signatures.

use axiom_types::{
    BlsPubkey, Preset, ValidatorIndex,
    constants::{
        DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_CONTRIBUTION_AND_PROOF,
        DOMAIN_SELECTION_PROOF, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, SYNC_COMMITTEE_SUBNET_COUNT,
    },
    fulu::{
        Attestation, BeaconState, IndexedAttestation, SignedAggregateAndProof,
        SignedContributionAndProof, SyncAggregatorSelectionData,
    },
};

use crate::{Detail, GossipError, signing_claim::SigningClaim};

/// A state read as the source of signers: keys, sync committees, and signing domains.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Signers<'a, P: Preset> {
    /// The state, usually the head's.
    state: &'a BeaconState<P>,
}

impl<'a, P: Preset> Signers<'a, P> {
    /// The signers a state knows.
    pub(crate) const fn of(state: &'a BeaconState<P>) -> Self {
        Self { state }
    }

    /// Checks an attestation aggregator's slot signature and its signature over the message.
    ///
    /// # Errors
    ///
    /// Rejects an unknown aggregator or an invalid signature.
    pub(crate) fn verify_aggregator(
        self,
        signed: &SignedAggregateAndProof<P>,
    ) -> Result<(), GossipError> {
        let message = &signed.message;
        let data = &message.aggregate.data;
        let state = self.state;
        let aggregator_detail = Detail::Validator(message.aggregator_index);
        // Committee membership was checked, so the index is in range for an honest message.
        let aggregator = state
            .validators
            .get(message.aggregator_index.as_usize())
            .ok_or_else(|| {
                GossipError::reject("aggregator is not a member of the committee")
                    .with(aggregator_detail)
            })?;
        // The selection proof signs the slot, and its hash decides who aggregates.
        let selection_domain = state.domain(DOMAIN_SELECTION_PROOF, data.target.epoch);
        if !SigningClaim::new(&data.slot, selection_domain, &message.selection_proof)
            .is_signed_by(&aggregator.pubkey)
        {
            return Err(
                GossipError::reject("invalid selection proof signature").with(aggregator_detail)
            );
        }
        // The outer signature binds the aggregate to the aggregator.
        let aggregate_domain = state.domain(DOMAIN_AGGREGATE_AND_PROOF, data.target.epoch);
        if !SigningClaim::new(message, aggregate_domain, &signed.signature)
            .is_signed_by(&aggregator.pubkey)
        {
            return Err(GossipError::reject("invalid aggregator signature").with(aggregator_detail));
        }
        Ok(())
    }

    /// Checks a sync contribution aggregator's selection proof and its signature over the message.
    ///
    /// # Errors
    ///
    /// Rejects an invalid signature.
    pub(crate) fn verify_contributor(
        self,
        pubkey: &BlsPubkey,
        signed: &SignedContributionAndProof<P>,
    ) -> Result<(), GossipError> {
        let message = &signed.message;
        let contribution = &message.contribution;
        let epoch = contribution.slot.epoch::<P>();
        let aggregator_detail = Detail::Validator(message.aggregator_index);
        // The selection proof signs the slot and subcommittee, and its hash decides who aggregates.
        let selection = SyncAggregatorSelectionData {
            slot: contribution.slot,
            subcommittee_index: contribution.subcommittee_index,
        };
        let selection_domain = self
            .state
            .domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, epoch);
        if !SigningClaim::new(&selection, selection_domain, &message.selection_proof)
            .is_signed_by(pubkey)
        {
            return Err(
                GossipError::reject("invalid selection proof signature").with(aggregator_detail)
            );
        }
        // The outer signature binds the contribution to the aggregator.
        let contribution_domain = self.state.domain(DOMAIN_CONTRIBUTION_AND_PROOF, epoch);
        if !SigningClaim::new(message, contribution_domain, &signed.signature).is_signed_by(pubkey)
        {
            return Err(GossipError::reject("invalid aggregator signature").with(aggregator_detail));
        }
        Ok(())
    }

    /// The sync committee whose members sign for the slot after the state's.
    ///
    /// Members for a slot sign the previous slot's block.
    /// At a period boundary that is the next committee.
    pub(crate) fn sync_committee_for_next_slot(self) -> Vec<BlsPubkey> {
        let state = self.state;
        let committee = if state.slot.sync_committee_period::<P>()
            == (state.slot + 1).sync_committee_period::<P>()
        {
            &state.current_sync_committee
        } else {
            &state.next_sync_committee
        };
        committee.pubkeys.to_vec()
    }

    /// Members of one sync subcommittee.
    ///
    /// See `get_sync_subcommittee_pubkeys` in the Altair p2p spec.
    pub(crate) fn sync_subcommittee(self, subcommittee: u64) -> Vec<BlsPubkey> {
        let size = (P::SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT) as usize;
        let start = subcommittee as usize * size;
        self.sync_committee_for_next_slot()
            .into_iter()
            .skip(start)
            .take(size)
            .collect()
    }

    /// Whether attesters, in any order and with repeats, signed an aggregate together.
    pub(crate) fn attested(
        self,
        mut attesters: Vec<ValidatorIndex>,
        aggregate: &Attestation<P>,
    ) -> bool {
        attesters.sort_unstable();
        attesters.dedup();
        let state = self.state;
        let keys: Vec<BlsPubkey> = attesters
            .iter()
            .map(|index| state.validators[index.as_usize()].pubkey)
            .collect();
        let domain = state.domain(DOMAIN_BEACON_ATTESTER, aggregate.data.target.epoch);
        SigningClaim::new(&aggregate.data, domain, &aggregate.signature).is_signed_by_all(&keys)
    }

    /// Whether an indexed attestation has sorted unique indices and a valid signature.
    pub(crate) fn is_valid_indexed_attestation(self, attestation: &IndexedAttestation<P>) -> bool {
        let indices = &attestation.attesting_indices;
        if indices.is_empty() || !indices.windows(2).all(|pair| pair[0] < pair[1]) {
            return false;
        }
        let state = self.state;
        let keys: Vec<BlsPubkey> = indices
            .iter()
            .map(|index| state.validators[index.as_usize()].pubkey)
            .collect();
        let domain = state.domain(DOMAIN_BEACON_ATTESTER, attestation.data.target.epoch);
        SigningClaim::new(&attestation.data, domain, &attestation.signature).is_signed_by_all(&keys)
    }
}
