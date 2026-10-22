//! Phase0 attestation rewards and penalties, scored from pending attestations.

use axiom_types::{
    Epoch, Gwei, Preset, ValidatorIndex,
    accessors::{CoreState, ForkState},
    phase0::BeaconState,
};

use super::participation::{PendingParticipation, VotePart};
use crate::{ActiveBalance, CachedState, StateError};

/// Components a fully correct vote is paid for: source, target, head, and inclusion delay.
///
/// See `BASE_REWARDS_PER_EPOCH` in the phase0 beacon chain spec.
const BASE_REWARDS_PER_EPOCH: u64 = 4;

/// Rewards and penalties per validator.
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

    /// Adds another set of deltas into this one, validator by validator.
    fn add(&mut self, other: &Self) {
        for (sum, delta) in self.rewards.iter_mut().zip(&other.rewards) {
            *sum += *delta;
        }
        for (sum, delta) in self.penalties.iter_mut().zip(&other.penalties) {
            *sum += *delta;
        }
    }

    /// Credits every reward, then debits every penalty, validator by validator.
    ///
    /// # Errors
    ///
    /// Fails when a balance overflows.
    pub fn apply<S: CoreState>(&self, state: &mut CachedState<'_, S>) -> Result<(), StateError> {
        for (index, (reward, penalty)) in self.rewards.iter().zip(&self.penalties).enumerate() {
            let index = ValidatorIndex::from(index);
            state.increase_balance(index, *reward)?;
            state.decrease_balance(index, *penalty)?;
        }
        Ok(())
    }
}

/// The rewards of the previous epoch's votes, component by component.
///
/// # Overview
///
/// A validator's base reward is its share of issuance for one component.
/// It scales with the effective balance over the square root of the total stake.
///
/// During an inactivity leak, correct votes earn a full base reward per component.
/// The leak's own penalty cancels that, so only absent validators lose stake.
///
/// See the rewards and penalties section of the phase0 beacon chain spec.
#[derive(Debug)]
pub struct AttestationRewards<'a, P: Preset> {
    /// The state at the end of the epoch.
    state: &'a BeaconState<P>,
    /// Who voted what.
    participation: &'a PendingParticipation,
    /// Validators active in the previous epoch, or slashed and not yet withdrawable.
    eligible: Vec<ValidatorIndex>,
    /// The base reward under the epoch's total active balance.
    base: BaseReward,
}

impl<'a, P: Preset> AttestationRewards<'a, P> {
    /// The rewards of a state's previous epoch.
    #[must_use]
    pub fn new(state: &'a BeaconState<P>, participation: &'a PendingParticipation) -> Self {
        Self {
            state,
            participation,
            eligible: state.eligible_validator_indices(),
            base: BaseReward::new(participation.total_active_balance()),
        }
    }

    /// Validators the epoch's rewards and penalties apply to, in index order.
    #[must_use]
    pub fn eligible(&self) -> &[ValidatorIndex] {
        &self.eligible
    }

    /// What a correct vote on one part earns a validator with an effective balance.
    ///
    /// This is the reward of the vote deltas, for a validator that made that part right.
    #[must_use]
    pub fn vote_reward(&self, part: VotePart, effective_balance: Gwei) -> Gwei {
        let base_reward = self.base.of::<P>(effective_balance);
        if self.state.is_in_inactivity_leak() {
            return base_reward;
        }
        // The increment is factored out of both balances so the product stays within 64 bits.
        let increment = P::EFFECTIVE_BALANCE_INCREMENT;
        let attesting = self.participation.previous_balance(part) / increment;
        let total = self.participation.total_active_balance().0 / increment;
        Gwei(base_reward.0 * attesting / total)
    }

    /// What an inclusion in the very next slot earns a validator with an effective balance.
    #[must_use]
    pub fn prompt_inclusion_reward(&self, effective_balance: Gwei) -> Gwei {
        self.base.of::<P>(effective_balance) - self.base.proposer_share::<P>(effective_balance)
    }

    /// What the inactivity leak charges a validator that voted the target correctly.
    ///
    /// Outside a leak it charges nothing.
    #[must_use]
    pub fn leak_penalty(&self, effective_balance: Gwei) -> Gwei {
        if !self.state.is_in_inactivity_leak() {
            return Gwei::ZERO;
        }
        self.base.of::<P>(effective_balance) * BASE_REWARDS_PER_EPOCH
            - self.base.proposer_share::<P>(effective_balance)
    }

    /// The deltas of one part of the vote.
    ///
    /// A correct voter earns its base reward in proportion to the stake that voted the same.
    /// Any other eligible validator pays the full base reward.
    ///
    /// See `get_attestation_component_deltas` in the phase0 beacon chain spec.
    #[must_use]
    pub fn vote_deltas(&self, part: VotePart) -> Deltas {
        let mut deltas = Deltas::zero(self.state.validators.len());
        for index in &self.eligible {
            let index = index.as_usize();
            if self.participation.has_previous(index, part) {
                let effective_balance = self.state.validators[index].effective_balance;
                deltas.rewards[index] += self.vote_reward(part, effective_balance);
            } else {
                deltas.penalties[index] += self.base_reward(index);
            }
        }
        deltas
    }

    /// Rewards for prompt inclusion, shared between each voter and the proposer that included it.
    ///
    /// The proposer takes an eighth of the voter's base reward.
    /// The voter takes the rest, divided by the delay of its earliest inclusion.
    ///
    /// See `get_inclusion_delay_deltas` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when an including proposer is not in the registry.
    pub fn inclusion_delay_deltas(&self) -> Result<Deltas, StateError> {
        let shares = self.inclusion_shares()?;
        let mut deltas = shares.attesters;
        deltas.add(&shares.proposers);
        Ok(deltas)
    }

    /// The inclusion rewards, split between what voters earn and what proposers earn.
    ///
    /// Their sum is the inclusion delay deltas.
    ///
    /// # Errors
    ///
    /// Fails when an including proposer is not in the registry.
    pub fn inclusion_shares(&self) -> Result<InclusionShares, StateError> {
        let registry_size = self.state.validators.len();
        let mut shares = InclusionShares {
            attesters: Deltas::zero(registry_size),
            proposers: Deltas::zero(registry_size),
        };
        for index in 0..registry_size {
            let Some(inclusion) = self.participation.earliest_inclusion(index) else {
                continue;
            };
            let proposer_reward = self.proposer_reward(index);
            let proposer = shares
                .proposers
                .rewards
                .get_mut(inclusion.proposer.as_usize())
                .ok_or(StateError::UnknownValidator {
                    index: inclusion.proposer,
                    registry_size,
                })?;
            *proposer += proposer_reward;
            // Invariant: block processing admits votes at least one slot old, so the delay is positive.
            let delay = inclusion.delay.max(1);
            shares.attesters.rewards[index] += (self.base_reward(index) - proposer_reward) / delay;
        }
        Ok(shares)
    }

    /// Penalties of the inactivity leak, which start once finality stalls.
    ///
    /// Every eligible validator pays back what a perfect vote earns, less the proposer's share.
    /// A validator that missed the target also loses its balance times the epochs since finality,
    /// over the fork's quotient, so absent stake drains quadratically in time.
    ///
    /// See `get_inactivity_penalty_deltas` in the phase0 beacon chain spec.
    #[must_use]
    pub fn inactivity_penalty_deltas(&self) -> Deltas {
        let mut deltas = Deltas::zero(self.state.validators.len());
        if !self.state.is_in_inactivity_leak() {
            return deltas;
        }
        let finality_delay = u128::from(self.state.finality_delay());
        let quotient = u128::from(BeaconState::<P>::FORK.inactivity_penalty_quotient::<P>());
        for index in &self.eligible {
            let index = index.as_usize();
            deltas.penalties[index] +=
                self.leak_penalty(self.state.validators[index].effective_balance);
            if !self.participation.has_previous(index, VotePart::Target) {
                let effective_balance =
                    u128::from(self.state.validators[index].effective_balance.0);
                let penalty = effective_balance * finality_delay / quotient;
                deltas.penalties[index] += Gwei(u64::try_from(penalty).unwrap_or(u64::MAX));
            }
        }
        deltas
    }

    /// Every component's deltas, summed per validator.
    ///
    /// See `get_attestation_deltas` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when an including proposer is not in the registry.
    pub fn total(&self) -> Result<Deltas, StateError> {
        let mut total = Deltas::zero(self.state.validators.len());
        for part in VotePart::ALL {
            total.add(&self.vote_deltas(part));
        }
        total.add(&self.inclusion_delay_deltas()?);
        total.add(&self.inactivity_penalty_deltas());
        Ok(total)
    }

    /// One component's share of issuance for a validator.
    ///
    /// See `get_base_reward` in the phase0 beacon chain spec.
    fn base_reward(&self, index: usize) -> Gwei {
        self.base
            .of::<P>(self.state.validators[index].effective_balance)
    }

    /// The proposer's share of a voter's inclusion reward.
    ///
    /// See `get_proposer_reward` in the phase0 beacon chain spec.
    fn proposer_reward(&self, index: usize) -> Gwei {
        self.base
            .proposer_share::<P>(self.state.validators[index].effective_balance)
    }
}

/// The inclusion delay rewards, by who earns them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InclusionShares {
    /// What each voter earns for its earliest inclusion.
    pub attesters: Deltas,
    /// What each proposer earns for the votes it included first.
    pub proposers: Deltas,
}

/// Phase0's base reward under one epoch's total active balance.
///
/// The square root of the total is taken once, since every validator's reward divides by it.
/// See `get_base_reward` in the phase0 beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseReward {
    /// Square root of the total active balance.
    total_root: u64,
}

impl BaseReward {
    /// The base reward under a total active balance.
    #[must_use]
    pub const fn new(total_active_balance: ActiveBalance) -> Self {
        Self {
            total_root: total_active_balance.0.0.isqrt(),
        }
    }

    /// One component's share of issuance for a validator with an effective balance.
    #[must_use]
    pub const fn of<P: Preset>(self, effective_balance: Gwei) -> Gwei {
        Gwei(effective_balance.0 * P::BASE_REWARD_FACTOR / self.total_root / BASE_REWARDS_PER_EPOCH)
    }

    /// The share of a voter's base reward its including proposer earns.
    ///
    /// See `get_proposer_reward` in the phase0 beacon chain spec.
    #[must_use]
    pub const fn proposer_share<P: Preset>(self, effective_balance: Gwei) -> Gwei {
        Gwei(self.of::<P>(effective_balance).0 / P::PROPOSER_REWARD_QUOTIENT)
    }
}

/// The epoch's attestation rewards and penalties, applied to balances.
///
/// Phase0 sums the components first, so a penalty saturates against the whole reward.
/// See `process_rewards_and_penalties` in the phase0 beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewardsAndPenalties {
    /// The epoch that is ending.
    current_epoch: Epoch,
    /// Total active balance of the ending epoch.
    total_active_balance: ActiveBalance,
}

impl RewardsAndPenalties {
    /// The rewards due at the end of an epoch.
    #[must_use]
    pub const fn new(current_epoch: Epoch, total_active_balance: ActiveBalance) -> Self {
        Self {
            current_epoch,
            total_active_balance,
        }
    }

    /// Pays the previous epoch's votes, except at genesis, which has no previous epoch.
    ///
    /// The votes are read only past genesis, as the spec reads them.
    ///
    /// # Errors
    ///
    /// Fails when a vote breaks an invariant or a balance overflows.
    pub fn apply<P: Preset>(
        self,
        state: &mut CachedState<'_, BeaconState<P>>,
    ) -> Result<(), StateError> {
        if self.current_epoch == Epoch::GENESIS {
            return Ok(());
        }
        let participation = PendingParticipation::new(state, self.total_active_balance)?;
        let deltas = AttestationRewards::new(state.beacon(), &participation).total()?;
        deltas.apply(state)
    }
}
