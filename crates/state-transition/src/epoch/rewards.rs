//! Participation rewards and penalties.

use axiom_types::{
    ChainConfig, Epoch, Gwei, Preset,
    constants::{
        PARTICIPATION_FLAG_WEIGHTS, TIMELY_HEAD_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
        WEIGHT_DENOMINATOR,
    },
};

use super::Participation;
use crate::{State, StateError};

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
    pub fn flag_index<P: Preset>(participation: &Participation<'_, P>, flag: usize) -> Self {
        let state = participation.state();
        let mut deltas = Self::zero(state.validators.len());
        let weight = PARTICIPATION_FLAG_WEIGHTS[flag];
        let increment = P::EFFECTIVE_BALANCE_INCREMENT;
        let total_active_balance = participation.total_active_balance();
        let participating_increments = participation
            .unslashed_participating_balance(flag, participation.previous_epoch())
            / increment;
        let active_increments = total_active_balance.0 / increment;
        let per_increment = total_active_balance.base_reward_per_increment::<P>();
        let in_leak = state.is_in_inactivity_leak();

        for index in state.eligible_validator_indices() {
            let index = index.as_usize();
            let base_reward =
                per_increment * (state.validators[index].effective_balance / increment);
            if participation.is_previous_participant(index, flag) {
                if !in_leak {
                    let numerator = u128::from(base_reward.0)
                        * u128::from(weight)
                        * u128::from(participating_increments);
                    let denominator =
                        u128::from(active_increments) * u128::from(WEIGHT_DENOMINATOR);
                    deltas.rewards[index] += Gwei((numerator / denominator) as u64);
                }
            } else if flag != TIMELY_HEAD_FLAG_INDEX {
                deltas.penalties[index] += base_reward * weight / WEIGHT_DENOMINATOR;
            }
        }
        deltas
    }

    /// Penalties for missing the target, scaled by each validator's inactivity score.
    ///
    /// The penalty grows linearly with the score, which grows linearly during a leak.
    /// An inactive stake therefore drains quadratically in time.
    ///
    /// See `get_inactivity_penalty_deltas` in the Bellatrix beacon chain spec.
    #[must_use]
    pub fn inactivity_penalties<P: Preset>(
        participation: &Participation<'_, P>,
        config: &ChainConfig,
    ) -> Self {
        let state = participation.state();
        let mut deltas = Self::zero(state.validators.len());
        let denominator = u128::from(config.inactivity_score_bias)
            * u128::from(P::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX);
        for index in state.eligible_validator_indices() {
            let index = index.as_usize();
            if !participation.is_previous_participant(index, TIMELY_TARGET_FLAG_INDEX) {
                let numerator = u128::from(state.validators[index].effective_balance.0)
                    * u128::from(state.inactivity_scores[index]);
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

/// Every component's deltas for one epoch: one per flag, then the inactivity penalties.
///
/// See `process_rewards_and_penalties` in the Altair beacon chain spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct RewardsAndPenalties {
    /// The components, in the order they apply.
    components: Vec<Deltas>,
}

impl RewardsAndPenalties {
    /// The components the ending epoch's participation earns.
    ///
    /// Rewards pay for the previous epoch, which genesis does not have.
    pub(super) fn new<P: Preset>(
        participation: &Participation<'_, P>,
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
    pub(super) fn apply<P: Preset>(self, state: &mut State<P>) -> Result<(), StateError> {
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
