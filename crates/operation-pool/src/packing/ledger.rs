//! What the state already credits each validator, and what a new credit pays the proposer.

use axiom_types::{
    Epoch, Gwei, ParticipationFlags, Preset, ValidatorIndex,
    accessors::CoreState,
    constants::{PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
};

/// Number of participation flags a vote can earn.
///
/// See `PARTICIPATION_FLAG_WEIGHTS` in the Altair beacon chain spec.
pub const FLAGS: usize = PARTICIPATION_FLAG_WEIGHTS.len();

/// Base rewards an epoch pays, of which the proposer takes a share.
///
/// See `BASE_REWARDS_PER_EPOCH` in the phase0 beacon chain spec.
const BASE_REWARDS_PER_EPOCH: u64 = 4;

/// How a fork pays the proposer for the votes its block includes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewardRule {
    /// Phase0: a share of each attester's base reward, for its first inclusion in the epoch.
    ///
    /// See `get_proposer_reward` in the phase0 beacon chain spec.
    FirstInclusion {
        /// Integer square root of the total active balance, in Gwei.
        total_balance_root: u64,
    },
    /// Altair on: a share of the base reward of every flag the vote newly sets.
    ///
    /// See `process_attestation` in the Altair beacon chain spec.
    ParticipationFlags {
        /// Base reward per increment of effective balance.
        base_reward_per_increment: Gwei,
    },
}

impl RewardRule {
    /// The proposer's reward for the credits of one attestation, given their summed rates.
    ///
    /// Altair divides each attestation's sum once, so the floor applies per attestation.
    /// See `process_attestation` in the Altair beacon chain spec.
    #[must_use]
    pub const fn proposer_reward(self, gain: u64) -> Gwei {
        match self {
            Self::FirstInclusion { .. } => Gwei(gain),
            Self::ParticipationFlags { .. } => {
                let denominator =
                    (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
                Gwei(gain / denominator)
            }
        }
    }

    /// What each flag pays the proposer when set for a validator of an effective balance.
    ///
    /// The values are proportional to the proposer's reward, which divides their sum once.
    /// Phase0 pays through the first flag only.
    #[must_use]
    pub fn rates<P: Preset>(self, effective_balance: Gwei) -> [u64; FLAGS] {
        match self {
            Self::FirstInclusion { total_balance_root } => {
                let base_reward = effective_balance.0 * P::BASE_REWARD_FACTOR
                    / total_balance_root.max(1)
                    / BASE_REWARDS_PER_EPOCH;
                [base_reward / P::PROPOSER_REWARD_QUOTIENT, 0, 0]
            }
            Self::ParticipationFlags {
                base_reward_per_increment,
            } => {
                let increments = effective_balance / P::EFFECTIVE_BALANCE_INCREMENT;
                let base_reward = base_reward_per_increment.0 * increments;
                PARTICIPATION_FLAG_WEIGHTS.map(|weight| base_reward * weight)
            }
        }
    }
}

/// The credits a block's votes compete for, at the state of the proposal slot.
///
/// # Overview
///
/// A vote pays only for credits its validator does not hold yet.
/// The ledger records the credits held, per validator, for the previous and current epochs.
/// Phase0 records a first inclusion as the first flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    /// How a credit pays.
    pub rule: RewardRule,
    /// The epoch of the state.
    pub current_epoch: Epoch,
    /// Credits held for the previous epoch's votes, by validator index.
    pub previous: Vec<ParticipationFlags>,
    /// Credits held for the current epoch's votes, by validator index.
    pub current: Vec<ParticipationFlags>,
}

impl Ledger {
    /// The credits a validator holds for votes targeting an epoch.
    ///
    /// Validators past the recorded lists hold none.
    #[must_use]
    pub fn credited(&self, target: Epoch, validator: ValidatorIndex) -> ParticipationFlags {
        let side = if target == self.current_epoch {
            &self.current
        } else {
            &self.previous
        };
        side.get(validator.as_usize()).copied().unwrap_or_default()
    }

    /// The rates of a validator of the state, by its effective balance.
    #[must_use]
    pub fn rates<S: CoreState>(&self, state: &S, validator: ValidatorIndex) -> [u64; FLAGS] {
        let effective_balance = state
            .validators()
            .get(validator.as_usize())
            .map_or(Gwei::ZERO, |record| record.effective_balance);
        self.rule.rates::<S::Preset>(effective_balance)
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Mainnet;

    use super::*;

    #[test]
    fn altair_rates_follow_the_flag_weights() {
        // A 32 ETH validator holds 32 increments; at 1000 Gwei per increment its base is 32000.
        let rule = RewardRule::ParticipationFlags {
            base_reward_per_increment: Gwei(1000),
        };

        // Source, target, and head weigh 14, 26, and 14 of 64.
        assert_eq!(
            rule.rates::<Mainnet>(Gwei(32_000_000_000)),
            [448_000, 832_000, 448_000]
        );
    }

    #[test]
    fn phase0_rates_pay_an_eighth_of_the_base_reward_through_the_first_flag() {
        // Total balance 2^40 Gwei has root 2^20 = 1048576.
        // Base reward: 32e9 * 64 / 1048576 / 4 = 488281, floor.
        // The proposer takes 1/8: 61035.
        let rule = RewardRule::FirstInclusion {
            total_balance_root: 1_048_576,
        };
        assert_eq!(rule.rates::<Mainnet>(Gwei(32_000_000_000)), [61_035, 0, 0]);
    }
}
