//! The sync aggregate step: rewarding the sync committee for signing the parent.

use axiom_bls::{PublicKey, Signature};
use axiom_types::{
    Preset, Root, SigningData, SyncAggregate, ValidatorIndex,
    constants::{DOMAIN_SYNC_COMMITTEE, PROPOSER_WEIGHT, SYNC_REWARD_WEIGHT, WEIGHT_DENOMINATOR},
};

use super::BlockProcessor;
use crate::{BlockError, State, StateError};

impl<P: Preset> BlockProcessor<'_, P> {
    /// Checks the sync committee's signature over the parent block, and settles its rewards.
    ///
    /// # Algorithm
    ///
    /// The participants' aggregate key is built the cheapest way.
    ///
    /// - Everyone signed: the committee's stored aggregate.
    /// - More than half signed: the stored aggregate minus the non-signers.
    /// - Otherwise: the sum of the signers.
    ///
    /// Each signer earns a fixed reward and each absentee loses the same amount.
    /// The proposer earns 8/56 of every signer's reward for including it.
    ///
    /// See `process_sync_aggregate` in the Altair beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the signature does not verify, or a committee member is not a validator.
    pub fn process_sync_aggregate(
        &mut self,
        aggregate: &SyncAggregate<P>,
    ) -> Result<(), BlockError> {
        let state = &self.state.beacon;
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
        for pubkey in &members {
            let index = self
                .state
                .validator_index(pubkey)
                .ok_or(BlockError::MalformedSignature)?;
            indices.push(index);
        }

        if self.signatures.is_enabled() {
            self.verify_sync_signature(aggregate, &indices, signing_root)?;
        }

        // Phase 2: rewards, as a share of one slot's sync reward budget.
        let total_active_increments = self.total_active_balance / P::EFFECTIVE_BALANCE_INCREMENT;
        let total_base_rewards = State::<P>::base_reward_per_increment(self.total_active_balance)
            * total_active_increments;
        let max_participant_rewards =
            total_base_rewards * SYNC_REWARD_WEIGHT / WEIGHT_DENOMINATOR / P::SLOTS_PER_EPOCH;
        let participant_reward = max_participant_rewards / P::SYNC_COMMITTEE_SIZE;
        let proposer_reward =
            participant_reward * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT);

        let proposer = self.state.beacon.beacon_proposer_index();
        for (index, bit) in indices
            .into_iter()
            .zip(aggregate.sync_committee_bits.iter())
        {
            if bit {
                self.state.increase_balance(index, participant_reward)?;
                self.state.increase_balance(proposer, proposer_reward)?;
            } else {
                self.state.decrease_balance(index, participant_reward)?;
            }
        }
        Ok(())
    }

    /// Queues the sync committee signature check, choosing the cheapest aggregate key.
    fn verify_sync_signature(
        &mut self,
        aggregate: &SyncAggregate<P>,
        members: &[ValidatorIndex],
        signing_root: Root,
    ) -> Result<(), BlockError> {
        let bits = &aggregate.sync_committee_bits;
        let participants = bits.count_ones() as u64;

        // Nobody signed: only the point at infinity is a valid empty signature.
        if participants == 0 {
            let signature = Signature::from_bytes(&aggregate.sync_committee_signature.0)
                .map_err(|_| BlockError::MalformedSignature)?;
            return if signature.is_infinity() {
                Ok(())
            } else {
                Err(BlockError::InvalidSignature)
            };
        }

        let key = if participants == P::SYNC_COMMITTEE_SIZE {
            PublicKey::from_bytes(&self.state.beacon.current_sync_committee.aggregate_pubkey.0)
                .map_err(|_| BlockError::MalformedSignature)?
        } else {
            let mut signers = Vec::new();
            let mut absentees = Vec::new();
            for (index, bit) in members.iter().zip(bits.iter()) {
                let key = self.state.public_key(*index)?;
                if bit {
                    signers.push(key);
                } else {
                    absentees.push(key);
                }
            }
            if participants > P::SYNC_COMMITTEE_SIZE / 2 {
                let total = PublicKey::from_bytes(
                    &self.state.beacon.current_sync_committee.aggregate_pubkey.0,
                )
                .map_err(|_| BlockError::MalformedSignature)?;
                let absent =
                    PublicKey::aggregate(&absentees).map_err(|_| BlockError::MalformedSignature)?;
                // An aggregate that cancels to infinity is not a valid key, so the signature fails.
                total
                    .subtract(&absent)
                    .map_err(|_| BlockError::InvalidSignature)?
            } else {
                PublicKey::aggregate(&signers).map_err(|_| BlockError::InvalidSignature)?
            }
        };
        self.verify_root(key, signing_root, &aggregate.sync_committee_signature)
    }
}
