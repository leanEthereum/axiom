//! The sync aggregate step: rewarding the sync committee for signing the parent.

use axiom_bls::{PublicKey, Signature};
use axiom_types::{
    Preset, Root, SigningData, SyncAggregate, ValidatorIndex,
    constants::{DOMAIN_SYNC_COMMITTEE, PROPOSER_WEIGHT, SYNC_REWARD_WEIGHT, WEIGHT_DENOMINATOR},
};

use super::{BlockProcessor, Operation};
use crate::{BlockError, StateError};

impl<P: Preset> Operation<P> for SyncAggregate<P> {
    /// Checks the sync committee's signature over the parent block, and settles its rewards.
    ///
    /// Each signer earns a fixed reward and each absentee loses the same amount.
    /// The proposer earns 8/56 of every signer's reward for including it.
    ///
    /// See `process_sync_aggregate` in the Altair beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        let state = &processor.state.beacon;
        let previous_slot = state.slot.saturating_sub(1);
        let block_root =
            state
                .block_root_at_slot(previous_slot)
                .ok_or(StateError::BlockRootOutOfRange {
                    slot: previous_slot,
                    state_slot: state.slot,
                })?;
        let domain = state.domain(DOMAIN_SYNC_COMMITTEE, previous_slot.epoch::<P>());
        let signing_root = SigningData::signing_root(&block_root, domain);

        // Resolve every member's index first: rewards need them, and keys come from the cache.
        let members = state
            .current_sync_committee
            .pubkeys
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let mut indices = Vec::with_capacity(members.len());
        for (seat, pubkey) in members.iter().enumerate() {
            let index = processor
                .state
                .validator_index(pubkey)
                .ok_or(StateError::UnknownSyncCommitteeMember { seat })?;
            indices.push(index);
        }

        if processor.signatures.is_enabled() {
            SyncCommitteeSignature {
                aggregate: self,
                members: &indices,
            }
            .queue(processor, signing_root)?;
        }

        // Phase 2: rewards, as a share of one slot's sync reward budget.
        let total_active_balance = processor.total_active_balance;
        let total_active_increments = total_active_balance.0 / P::EFFECTIVE_BALANCE_INCREMENT;
        let total_base_rewards =
            total_active_balance.base_reward_per_increment::<P>() * total_active_increments;
        let max_participant_rewards =
            total_base_rewards * SYNC_REWARD_WEIGHT / WEIGHT_DENOMINATOR / P::SLOTS_PER_EPOCH;
        let participant_reward = max_participant_rewards / P::SYNC_COMMITTEE_SIZE;
        let proposer_reward =
            participant_reward * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT);

        let proposer = processor.state.beacon.beacon_proposer_index();
        for (index, bit) in indices.into_iter().zip(self.sync_committee_bits.iter()) {
            if bit {
                processor
                    .state
                    .increase_balance(index, participant_reward)?;
                processor
                    .state
                    .increase_balance(proposer, proposer_reward)?;
            } else {
                processor
                    .state
                    .decrease_balance(index, participant_reward)?;
            }
        }
        Ok(())
    }
}

/// A sync aggregate's signature, with the committee members its bits refer to.
#[derive(Debug)]
struct SyncCommitteeSignature<'a, P: Preset> {
    /// The aggregate: participation bits and the signature.
    aggregate: &'a SyncAggregate<P>,
    /// Validator index of each committee seat.
    members: &'a [ValidatorIndex],
}

impl<P: Preset> SyncCommitteeSignature<'_, P> {
    /// Queues the signature check, choosing the cheapest aggregate key.
    ///
    /// # Algorithm
    ///
    /// - Nobody signed: only the point at infinity is valid, checked at once.
    /// - Everyone signed: the committee's stored aggregate.
    /// - More than half signed: the stored aggregate minus the non-signers.
    /// - Otherwise: the sum of the signers.
    fn queue(
        &self,
        processor: &mut BlockProcessor<'_, P>,
        signing_root: Root,
    ) -> Result<(), BlockError> {
        let bits = &self.aggregate.sync_committee_bits;
        let signature = &self.aggregate.sync_committee_signature;
        let participants = bits.count_ones() as u64;

        if participants == 0 {
            let signature = Signature::from_bytes(&signature.0).map_err(|source| {
                BlockError::MalformedSignature {
                    root: signing_root,
                    source,
                }
            })?;
            return if signature.is_infinity() {
                Ok(())
            } else {
                Err(BlockError::InvalidSignature { signatures: 1 })
            };
        }

        let key = if participants == P::SYNC_COMMITTEE_SIZE {
            Self::committee_key(processor)?
        } else {
            let mut signers = Vec::new();
            let mut absentees = Vec::new();
            for (index, bit) in self.members.iter().zip(bits.iter()) {
                let key = processor.state.public_key(*index)?;
                if bit {
                    signers.push(key);
                } else {
                    absentees.push(key);
                }
            }
            if participants > P::SYNC_COMMITTEE_SIZE / 2 {
                let total = Self::committee_key(processor)?;
                let absent =
                    PublicKey::aggregate(&absentees).map_err(BlockError::InvalidAggregateKey)?;
                // An aggregate that cancels to infinity is not a valid key, so the signature fails.
                total
                    .subtract(&absent)
                    .map_err(BlockError::InvalidAggregateKey)?
            } else {
                PublicKey::aggregate(&signers).map_err(BlockError::InvalidAggregateKey)?
            }
        };
        processor.verify_root(key, signing_root, signature)
    }

    /// The aggregate key of the whole current committee, as the state stores it.
    fn committee_key(processor: &BlockProcessor<'_, P>) -> Result<PublicKey, BlockError> {
        let stored = &processor
            .state
            .beacon
            .current_sync_committee
            .aggregate_pubkey;
        PublicKey::from_bytes(&stored.0)
            .map_err(|source| StateError::MalformedSyncCommitteeKey(source).into())
    }
}
