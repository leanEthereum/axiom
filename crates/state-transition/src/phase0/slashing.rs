//! Slashing a validator: the exit, the penalty, and the whistleblower's reward.

use axiom_types::{
    Preset, ValidatorIndex,
    constants::{PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
};

use crate::{Fork, Registry, StateError};

/// A validator about to be slashed, and who reported it.
///
/// Phase0 through Electra share this rule and differ only in its constants.
/// Each fork's penalty and reward quotients come from the fork's constant table.
/// See `slash_validator` in the phase0, Altair, Bellatrix, and Electra beacon chain specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slashing {
    /// The validator slashed.
    pub slashed: ValidatorIndex,
    /// The validator that reported it, or nothing when the proposer did.
    pub whistleblower: Option<ValidatorIndex>,
}

impl Slashing {
    /// Slashes the validator, and pays the proposer and the whistleblower.
    ///
    /// # Algorithm
    ///
    /// 1. The validator exits, and stays unwithdrawable for half the slashings vector.
    /// 2. Its effective balance joins the epoch's slashed total for the correlation penalty.
    /// 3. It loses an initial penalty, its effective balance over the fork's quotient.
    /// 4. The whistleblower earns its effective balance over the fork's reward quotient.
    /// 5. The proposer takes 8/64 of that reward.
    ///
    /// Phase0 gave the proposer the reward over a quotient of 8, the same 8/64.
    ///
    /// # Errors
    ///
    /// Fails when a validator does not exist or a balance overflows.
    pub fn apply<S: Fork>(self, registry: &mut Registry<'_, S>) -> Result<(), StateError> {
        let epoch = registry.state.beacon().current_epoch();
        registry.initiate_exit(self.slashed)?;

        let state = &mut *registry.state.beacon;
        let validator = &mut state.validators_mut()[self.slashed.as_usize()];
        validator.slashed = true;
        validator.withdrawable_epoch = validator
            .withdrawable_epoch
            .max(epoch.saturating_add(S::Preset::EPOCHS_PER_SLASHINGS_VECTOR));
        let effective_balance = validator.effective_balance;

        let slot = (epoch % S::Preset::EPOCHS_PER_SLASHINGS_VECTOR) as usize;
        let slashings = state.slashings_mut();
        slashings[slot] =
            slashings[slot]
                .checked_add(effective_balance)
                .ok_or(StateError::Overflow {
                    quantity: "slashed balance of the epoch",
                })?;
        let penalty = effective_balance / S::FORK.min_slashing_penalty_quotient::<S::Preset>();
        registry.state.decrease_balance(self.slashed, penalty)?;

        let proposer = registry.state.proposer()?;
        let whistleblower = self.whistleblower.unwrap_or(proposer);
        let whistleblower_reward =
            effective_balance / S::FORK.whistleblower_reward_quotient::<S::Preset>();
        let proposer_reward = whistleblower_reward * PROPOSER_WEIGHT / WEIGHT_DENOMINATOR;
        registry.state.increase_balance(proposer, proposer_reward)?;
        let whistleblower_share = whistleblower_reward - proposer_reward;
        registry
            .state
            .increase_balance(whistleblower, whistleblower_share)?;
        // A block's slashing has no other whistleblower, so its proposer takes both shares.
        let ledger = &mut registry.state.caches.proposer_ledger;
        ledger.slashing += proposer_reward;
        if whistleblower == proposer {
            ledger.slashing += whistleblower_share;
        }
        Ok(())
    }
}
