//! Participation rewards and penalties.

use axiom_types::{
    ChainConfig, Epoch, Gwei, Preset,
    accessors::{ForkState, ParticipationState},
    constants::{
        PARTICIPATION_FLAG_WEIGHTS, TIMELY_HEAD_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
        WEIGHT_DENOMINATOR,
    },
};

use super::Participation;
use crate::{CachedState, StateError};

/// Rewards and penalties of one component, per validator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Deltas {
    /// Amounts credited.
    pub rewards: Vec<Gwei>,
    /// Amounts debited.
    pub penalties: Vec<Gwei>,
}

impl Deltas {
    /// Rewards and penalties for one participation flag.
    ///
    /// A participant earns its share in proportion to the stake that also participated.
    /// An absentee pays the full share, except for the head flag, which never penalizes.
    /// During a leak participants earn nothing, so the leak can shift the balance of power.
    ///
    /// See `get_flag_index_deltas` in the Altair beacon chain spec.
    #[must_use]
    pub fn flag_index<S: ParticipationState + ?Sized>(
        participation: &Participation<'_, S>,
        flag: usize,
    ) -> Self {
        let state = participation.state();
        let validators = state.validators();
        let mut deltas = Self::zero(validators.len());
        let rates = FlagReward::new(participation, flag);
        for index in state.eligible_validator_indices() {
            let index = index.as_usize();
            let base_reward = rates.base_reward(validators[index].effective_balance);
            if participation.is_previous_participant(index, flag) {
                deltas.rewards[index] += rates.reward(base_reward);
            } else {
                deltas.penalties[index] += rates.penalty(base_reward);
            }
        }
        deltas
    }

    /// Penalties for missing the target, scaled by each validator's inactivity score.
    ///
    /// The penalty grows linearly with the score, which grows linearly during a leak.
    /// An inactive stake therefore drains quadratically in time.
    /// Altair and Bellatrix lowered the quotient, which the fork's constant table holds.
    ///
    /// See `get_inactivity_penalty_deltas` in the Altair and Bellatrix beacon chain specs.
    #[must_use]
    pub fn inactivity_penalties<S: ParticipationState + ForkState>(
        participation: &Participation<'_, S>,
        config: &ChainConfig,
    ) -> Self {
        let state = participation.state();
        let validators = state.validators();
        let scores = state.inactivity_scores();
        let mut deltas = Self::zero(validators.len());
        let denominator = u128::from(config.inactivity_score_bias)
            * u128::from(S::FORK.inactivity_penalty_quotient::<S::Preset>());
        for index in state.eligible_validator_indices() {
            let index = index.as_usize();
            if !participation.is_previous_participant(index, TIMELY_TARGET_FLAG_INDEX) {
                let numerator =
                    u128::from(validators[index].effective_balance.0) * u128::from(scores[index]);
                deltas.penalties[index] += Gwei((numerator / denominator) as u64);
            }
        }
        deltas
    }

    /// All-zero deltas for a registry of a given size.
    fn zero(count: usize) -> Self {
        Self {
            rewards: vec![Gwei::ZERO; count],
            penalties: vec![Gwei::ZERO; count],
        }
    }
}

/// What one participation flag pays a participant and charges an absentee in an epoch.
///
/// The rates depend only on the epoch's totals, so one value serves every validator.
/// See `get_flag_index_deltas` in the Altair beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlagReward {
    /// The flag.
    flag: usize,
    /// The flag's share of the base reward, over the weight denominator.
    weight: u64,
    /// Increments of unslashed stake that earned the flag in the previous epoch.
    participating_increments: u64,
    /// Increments of active stake.
    active_increments: u64,
    /// Base reward per increment of effective balance.
    per_increment: Gwei,
    /// Increment of effective balance.
    increment: Gwei,
    /// Whether finality stalls, which withholds every flag reward.
    in_leak: bool,
}

impl FlagReward {
    /// The rates of a flag in the epoch a participation view ends.
    #[must_use]
    pub fn new<S: ParticipationState + ?Sized>(
        participation: &Participation<'_, S>,
        flag: usize,
    ) -> Self {
        let increment = S::Preset::EFFECTIVE_BALANCE_INCREMENT;
        let total_active_balance = participation.total_active_balance();
        Self {
            flag,
            weight: PARTICIPATION_FLAG_WEIGHTS[flag],
            participating_increments: participation
                .unslashed_participating_balance(flag, participation.previous_epoch())
                / increment,
            active_increments: total_active_balance.0 / increment,
            per_increment: total_active_balance.base_reward_per_increment::<S::Preset>(),
            increment,
            in_leak: participation.state().is_in_inactivity_leak(),
        }
    }

    /// The base reward of a validator with an effective balance.
    ///
    /// See `get_base_reward` in the Altair beacon chain spec.
    #[must_use]
    pub fn base_reward(&self, effective_balance: Gwei) -> Gwei {
        self.per_increment * (effective_balance / self.increment)
    }

    /// What a participant with a base reward earns.
    #[must_use]
    pub fn reward(&self, base_reward: Gwei) -> Gwei {
        if self.in_leak {
            return Gwei::ZERO;
        }
        // Bound: base reward, weight, and increments each fit 64 bits, so the product fits 128.
        let numerator = u128::from(base_reward.0)
            * u128::from(self.weight)
            * u128::from(self.participating_increments);
        let denominator = u128::from(self.active_increments) * u128::from(WEIGHT_DENOMINATOR);
        Gwei((numerator / denominator) as u64)
    }

    /// What an absentee with a base reward pays.
    #[must_use]
    pub fn penalty(&self, base_reward: Gwei) -> Gwei {
        if self.flag == TIMELY_HEAD_FLAG_INDEX {
            return Gwei::ZERO;
        }
        base_reward * self.weight / WEIGHT_DENOMINATOR
    }
}

/// Every component's deltas for one epoch: one per flag, then the inactivity penalties.
///
/// See `process_rewards_and_penalties` in the Altair beacon chain spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RewardsAndPenalties {
    /// The components, in the order they apply.
    components: Vec<Deltas>,
}

impl RewardsAndPenalties {
    /// The components the ending epoch's participation earns.
    ///
    /// Rewards pay for the previous epoch, which genesis does not have.
    #[must_use]
    pub fn new<S: ParticipationState + ForkState>(
        participation: &Participation<'_, S>,
        config: &ChainConfig,
    ) -> Self {
        if participation.current_epoch() == Epoch::GENESIS {
            return Self::default();
        }
        let mut components: Vec<Deltas> = (0..PARTICIPATION_FLAG_WEIGHTS.len())
            .map(|flag| Deltas::flag_index(participation, flag))
            .collect();
        components.push(Deltas::inactivity_penalties(participation, config));
        Self { components }
    }

    /// Credits and debits every component.
    ///
    /// # Errors
    ///
    /// Fails when a balance overflows.
    pub fn apply<S: ParticipationState>(
        self,
        state: &mut CachedState<'_, S>,
    ) -> Result<(), StateError> {
        // Components apply in order, so a penalty saturates against the rewards before it.
        for deltas in self.components {
            for (index, (reward, penalty)) in
                deltas.rewards.iter().zip(&deltas.penalties).enumerate()
            {
                let index = index.into();
                state.increase_balance(index, *reward)?;
                state.decrease_balance(index, *penalty)?;
            }
        }
        Ok(())
    }
}
