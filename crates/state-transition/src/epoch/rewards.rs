//! Participation rewards and penalties.

use axiom_types::{
    Epoch, Gwei, Preset,
    constants::{
        PARTICIPATION_FLAG_WEIGHTS, TIMELY_HEAD_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
        WEIGHT_DENOMINATOR,
    },
};

use super::EpochProcessor;
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
    /// All-zero deltas for a registry of a given size.
    fn zero(count: usize) -> Self {
        Self {
            rewards: vec![Gwei::ZERO; count],
            penalties: vec![Gwei::ZERO; count],
        }
    }
}

impl<P: Preset> EpochProcessor<'_, P> {
    /// Applies the flag rewards and the inactivity penalties, component by component.
    ///
    /// See `process_rewards_and_penalties` in the Altair beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when a balance overflows.
    pub fn process_rewards_and_penalties(&mut self) -> Result<(), StateError> {
        // Rewards pay for the previous epoch, which genesis does not have.
        if self.current_epoch == Epoch::GENESIS {
            return Ok(());
        }
        let mut components: Vec<Deltas> = (0..PARTICIPATION_FLAG_WEIGHTS.len())
            .map(|flag| self.flag_index_deltas(flag))
            .collect();
        components.push(self.inactivity_penalty_deltas());

        // Components apply in order, so a penalty saturates against the rewards before it.
        for deltas in components {
            for (index, (reward, penalty)) in
                deltas.rewards.iter().zip(&deltas.penalties).enumerate()
            {
                let index = index.into();
                self.state.increase_balance(index, *reward)?;
                self.state.decrease_balance(index, *penalty)?;
            }
        }
        Ok(())
    }

    /// Rewards and penalties for one participation flag.
    ///
    /// A participant earns its share in proportion to the stake that also participated.
    /// An absentee pays the full share, except for the head flag, which never penalizes.
    /// During a leak participants earn nothing, so the leak can shift the balance of power.
    ///
    /// See `get_flag_index_deltas` in the Altair beacon chain spec.
    #[must_use]
    pub fn flag_index_deltas(&self, flag: usize) -> Deltas {
        let beacon = &self.state.beacon;
        let mut deltas = Deltas::zero(beacon.validators.len());
        let weight = PARTICIPATION_FLAG_WEIGHTS[flag];
        let increment = P::EFFECTIVE_BALANCE_INCREMENT;
        let participating_increments =
            self.unslashed_participating_balance(flag, self.previous_epoch) / increment;
        let active_increments = self.total_active_balance / increment;
        let per_increment = State::<P>::base_reward_per_increment(self.total_active_balance);
        let in_leak = beacon.is_in_inactivity_leak();

        for index in beacon.eligible_validator_indices() {
            let index = index.as_usize();
            let base_reward =
                per_increment * (beacon.validators[index].effective_balance / increment);
            if self.is_previous_participant(index, flag) {
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
    pub fn inactivity_penalty_deltas(&self) -> Deltas {
        let beacon = &self.state.beacon;
        let mut deltas = Deltas::zero(beacon.validators.len());
        let denominator = u128::from(self.config.inactivity_score_bias)
            * u128::from(P::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX);
        for index in beacon.eligible_validator_indices() {
            let index = index.as_usize();
            if !self.is_previous_participant(index, TIMELY_TARGET_FLAG_INDEX) {
                let numerator = u128::from(beacon.validators[index].effective_balance.0)
                    * u128::from(beacon.inactivity_scores[index]);
                deltas.penalties[index] += Gwei((numerator / denominator) as u64);
            }
        }
        deltas
    }
}
