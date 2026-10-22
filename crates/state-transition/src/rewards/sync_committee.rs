//! What a block's sync aggregate pays or charges each sync committee member.

use axiom_types::{ChainConfig, Gwei, Preset, ValidatorIndex, accessors::CoreState, combined};

use super::{RewardsError, SignedGwei};
use crate::{ActiveBalance, State, StateError, altair::block::SyncRewardRates};

/// One sync committee member's reward from one block, negative when it did not sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncCommitteeReward {
    /// The member.
    pub validator_index: ValidatorIndex,
    /// What its seats earned or lost.
    pub reward: SignedGwei,
}

impl SyncCommitteeReward {
    /// The rewards of every member of the committee a block's sync aggregate speaks for.
    ///
    /// A validator holding several seats gets one entry, summing its seats, in first-seat order.
    /// The amounts are nominal: a penalty larger than a balance takes only the balance.
    /// See `process_sync_aggregate` in the Altair beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails before Altair, or when a seat's key is not in the registry.
    pub fn of_block<P: Preset>(
        mut state: State<P>,
        block: &combined::SignedBeaconBlock<P>,
        config: &ChainConfig,
    ) -> Result<Vec<Self>, RewardsError> {
        let slot = block.slot();
        if slot > state.beacon().slot() {
            state.process_slots(config, slot)?;
        }
        let no_committee = || RewardsError::NoSyncCommittee(block.fork_name());
        let aggregate = block.sync_aggregate().ok_or_else(no_committee)?;
        let members: Vec<_> = state
            .beacon()
            .sync_committees()
            .ok_or_else(no_committee)?
            .current_sync_committee()
            .pubkeys
            .iter()
            .copied()
            .collect();
        let rates = SyncRewardRates::new::<P>(ActiveBalance::of(state.beacon().as_core()));

        let mut rewards: Vec<Self> = Vec::with_capacity(members.len());
        for (seat, (pubkey, signed)) in members
            .iter()
            .zip(aggregate.sync_committee_bits.iter())
            .enumerate()
        {
            let validator_index = state
                .validator_index(pubkey)
                .ok_or(StateError::UnknownSyncCommitteeMember { seat })?;
            let amount = if signed {
                SignedGwei::net(rates.participant, Gwei::ZERO)
            } else {
                SignedGwei::net(Gwei::ZERO, rates.participant)
            };
            match rewards
                .iter_mut()
                .find(|reward| reward.validator_index == validator_index)
            {
                Some(reward) => reward.reward.0 = reward.reward.0.saturating_add(amount.0),
                None => rewards.push(Self {
                    validator_index,
                    reward: amount,
                }),
            }
        }
        Ok(rewards)
    }
}
