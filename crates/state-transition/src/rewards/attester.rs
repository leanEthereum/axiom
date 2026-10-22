//! What an epoch's attestations earn each validator, component by component.

use std::collections::BTreeSet;

use axiom_types::{
    ChainConfig, Epoch, Gwei, Preset, Slot, ValidatorIndex,
    accessors::{CoreState, ForkState, ParticipationState},
    constants::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
};

use super::{RewardsError, SignedGwei};
use crate::{
    EpochStep, State, StateError,
    altair::epoch::{Deltas, FlagReward, Participation},
    phase0::epoch::{AttestationRewards, VotePart},
};

/// What one validator's votes of an epoch earned, as the epoch transition pays them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttesterReward {
    /// The validator.
    pub validator_index: ValidatorIndex,
    /// Net reward for the head vote.
    pub head: SignedGwei,
    /// Net reward for the target vote.
    pub target: SignedGwei,
    /// Net reward for the source vote.
    pub source: SignedGwei,
    /// Reward for prompt inclusion, which only phase0 pays.
    pub inclusion_delay: Option<Gwei>,
    /// The inactivity penalty, as a negative amount.
    pub inactivity: SignedGwei,
}

/// What perfect votes of an epoch earn a validator of one effective balance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdealAttesterReward {
    /// The effective balance.
    pub effective_balance: Gwei,
    /// Reward for a correct head vote.
    pub head: SignedGwei,
    /// Reward for a correct target vote.
    pub target: SignedGwei,
    /// Reward for a correct source vote.
    pub source: SignedGwei,
    /// Reward for inclusion in the next slot, which only phase0 pays.
    pub inclusion_delay: Option<Gwei>,
    /// The inactivity penalty a perfect voter still pays, as a negative amount.
    pub inactivity: SignedGwei,
}

/// The attestation rewards of one epoch, for every validator they apply to.
///
/// # Overview
///
/// The epoch transition at the end of epoch e + 1 pays the votes of epoch e.
/// This splits that payment into its components, per validator.
///
/// Each validator's components sum to what the transition credits it for its own votes.
/// In phase0 a proposer also earns from the votes it included, which is not counted here.
///
/// The ideal rewards list one entry per effective balance held by an eligible validator.
///
/// See `process_rewards_and_penalties` in the phase0 and Altair beacon chain specs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttesterRewards {
    /// Perfect-vote rewards, by ascending effective balance.
    pub ideal: Vec<IdealAttesterReward>,
    /// Actual rewards, by ascending validator index.
    pub validators: Vec<AttesterReward>,
}

impl AttesterRewards {
    /// The rewards of an epoch's votes, computed from a state before the epoch after it ends.
    ///
    /// The state advances through empty slots to the last slot of the next epoch.
    /// The epoch steps that precede the rewards run on it, as the transition runs them.
    /// The state must not be past that slot.
    ///
    /// # Errors
    ///
    /// Fails when the state is past the slot, or a step breaks an invariant.
    pub fn of_epoch<P: Preset>(
        mut state: State<P>,
        config: &ChainConfig,
        epoch: Epoch,
    ) -> Result<Self, RewardsError> {
        // Timing: epoch e's votes are paid at the end of the last slot of epoch e + 1.
        let paid_at = Slot((epoch.0 + 2) * P::SLOTS_PER_EPOCH - 1);
        let slot = state.beacon().slot();
        if slot > paid_at {
            return Err(RewardsError::StatePastEpoch {
                epoch,
                slot,
                last: paid_at,
            });
        }
        if slot < paid_at {
            state.process_slots(config, paid_at)?;
        }
        state.process_epoch_steps_before(config, EpochStep::RewardsAndPenalties)?;
        Ok(state.attester_rewards(config)?)
    }

    /// The rewards of a phase0 epoch, from its pending attestations.
    ///
    /// # Errors
    ///
    /// Fails when an including proposer is not in the registry.
    pub fn of_pending<P: Preset>(
        rewards: &AttestationRewards<'_, P>,
        state: &impl CoreState,
    ) -> Result<Self, StateError> {
        let source = rewards.vote_deltas(VotePart::Source);
        let target = rewards.vote_deltas(VotePart::Target);
        let head = rewards.vote_deltas(VotePart::Head);
        let inclusion = rewards.inclusion_shares()?.attesters;
        let inactivity = rewards.inactivity_penalty_deltas();
        let validators = rewards
            .eligible()
            .iter()
            .map(|index| {
                let at = index.as_usize();
                AttesterReward {
                    validator_index: *index,
                    head: SignedGwei::net(head.rewards[at], head.penalties[at]),
                    target: SignedGwei::net(target.rewards[at], target.penalties[at]),
                    source: SignedGwei::net(source.rewards[at], source.penalties[at]),
                    inclusion_delay: Some(inclusion.rewards[at]),
                    inactivity: SignedGwei::net(inactivity.rewards[at], inactivity.penalties[at]),
                }
            })
            .collect();
        let ideal = Self::balances(state, rewards.eligible())
            .map(|effective_balance| IdealAttesterReward {
                effective_balance,
                head: rewards
                    .vote_reward(VotePart::Head, effective_balance)
                    .into(),
                target: rewards
                    .vote_reward(VotePart::Target, effective_balance)
                    .into(),
                source: rewards
                    .vote_reward(VotePart::Source, effective_balance)
                    .into(),
                inclusion_delay: Some(rewards.prompt_inclusion_reward(effective_balance)),
                inactivity: SignedGwei::net(Gwei::ZERO, rewards.leak_penalty(effective_balance)),
            })
            .collect();
        Ok(Self { ideal, validators })
    }

    /// The rewards of an epoch scored by participation flags, from Altair on.
    #[must_use]
    pub fn of_participation<S: ParticipationState + ForkState>(
        participation: &Participation<'_, S>,
        config: &ChainConfig,
    ) -> Self {
        let state = participation.state();
        let eligible = state.eligible_validator_indices();
        let flag_deltas = |flag| Deltas::flag_index(participation, flag);
        let (source, target, head) = (
            flag_deltas(TIMELY_SOURCE_FLAG_INDEX),
            flag_deltas(TIMELY_TARGET_FLAG_INDEX),
            flag_deltas(TIMELY_HEAD_FLAG_INDEX),
        );
        let inactivity = Deltas::inactivity_penalties(participation, config);
        let validators = eligible
            .iter()
            .map(|index| {
                let at = index.as_usize();
                AttesterReward {
                    validator_index: *index,
                    head: SignedGwei::net(head.rewards[at], head.penalties[at]),
                    target: SignedGwei::net(target.rewards[at], target.penalties[at]),
                    source: SignedGwei::net(source.rewards[at], source.penalties[at]),
                    inclusion_delay: None,
                    inactivity: SignedGwei::net(inactivity.rewards[at], inactivity.penalties[at]),
                }
            })
            .collect();
        let rates = |flag| FlagReward::new(participation, flag);
        let (source, target, head) = (
            rates(TIMELY_SOURCE_FLAG_INDEX),
            rates(TIMELY_TARGET_FLAG_INDEX),
            rates(TIMELY_HEAD_FLAG_INDEX),
        );
        let ideal = Self::balances(state, &eligible)
            .map(|effective_balance| {
                let earned = |rate: FlagReward| rate.reward(rate.base_reward(effective_balance));
                IdealAttesterReward {
                    effective_balance,
                    head: earned(head).into(),
                    target: earned(target).into(),
                    source: earned(source).into(),
                    inclusion_delay: None,
                    // A voter that hit its target pays no inactivity penalty.
                    inactivity: SignedGwei::default(),
                }
            })
            .collect();
        Self { ideal, validators }
    }

    /// The distinct effective balances of some validators, ascending.
    fn balances(
        state: &(impl CoreState + ?Sized),
        indices: &[ValidatorIndex],
    ) -> impl Iterator<Item = Gwei> {
        let validators = state.validators();
        indices
            .iter()
            .map(|index| validators[index.as_usize()].effective_balance)
            .collect::<BTreeSet<_>>()
            .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, phase0};

    use super::*;

    #[test]
    fn a_state_past_the_paying_slot_cannot_report_the_epoch() {
        // Fixture state: slot 100, while epoch 1's votes are paid after slot 23.
        let state = State::new(phase0::BeaconState::<Minimal> {
            slot: Slot(100),
            ..phase0::BeaconState::default()
        });
        assert_eq!(
            AttesterRewards::of_epoch(state, &ChainConfig::minimal(), Epoch(1)),
            Err(RewardsError::StatePastEpoch {
                epoch: Epoch(1),
                slot: Slot(100),
                last: Slot(23),
            })
        );
    }
}
