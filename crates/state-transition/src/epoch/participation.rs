//! The participation of the ending epoch, as rewards and finality read it.

use axiom_types::{BeaconState, Epoch, Gwei, Preset};

use crate::ActiveBalance;

/// A read view of who voted what in the ending epoch and the one before it.
///
/// The state keeps participation flags for exactly these two epochs.
#[derive(Clone, Copy, Debug)]
pub struct Participation<'a, P: Preset> {
    /// The state at the last slot of the ending epoch.
    state: &'a BeaconState<P>,
    /// The epoch that is ending.
    current_epoch: Epoch,
    /// The epoch before it.
    previous_epoch: Epoch,
    /// Total active balance of the ending epoch.
    total_active_balance: ActiveBalance,
}

impl<'a, P: Preset> Participation<'a, P> {
    /// The view of a state, under its epoch's total active balance.
    #[must_use]
    pub const fn new(state: &'a BeaconState<P>, total_active_balance: ActiveBalance) -> Self {
        Self {
            state,
            current_epoch: state.current_epoch(),
            previous_epoch: state.previous_epoch(),
            total_active_balance,
        }
    }

    /// The state viewed.
    #[must_use]
    pub const fn state(&self) -> &'a BeaconState<P> {
        self.state
    }

    /// The epoch that is ending.
    #[must_use]
    pub const fn current_epoch(&self) -> Epoch {
        self.current_epoch
    }

    /// The epoch before it.
    #[must_use]
    pub const fn previous_epoch(&self) -> Epoch {
        self.previous_epoch
    }

    /// Total active balance of the ending epoch.
    #[must_use]
    pub const fn total_active_balance(&self) -> ActiveBalance {
        self.total_active_balance
    }

    /// Total effective balance of unslashed validators with a flag, in an epoch.
    ///
    /// The epoch is the previous or the current one, whose participation the state keeps.
    /// The total never falls below one increment, so it can divide.
    ///
    /// See `get_unslashed_participating_balance` in the Altair beacon chain spec.
    #[must_use]
    pub fn unslashed_participating_balance(&self, flag: usize, epoch: Epoch) -> Gwei {
        let state = self.state;
        let participation = if epoch == self.current_epoch {
            &state.current_epoch_participation
        } else {
            &state.previous_epoch_participation
        };
        let sum: Gwei = state
            .validators
            .iter()
            .zip(participation.iter())
            .filter(|(validator, flags)| {
                validator.is_active_at(epoch) && !validator.slashed && flags.has(flag)
            })
            .map(|(validator, _)| validator.effective_balance)
            .sum();
        sum.max(P::EFFECTIVE_BALANCE_INCREMENT)
    }

    /// Whether a validator is an unslashed participant with a flag in the previous epoch.
    #[must_use]
    pub fn is_previous_participant(&self, index: usize, flag: usize) -> bool {
        let validator = &self.state.validators[index];
        validator.is_active_at(self.previous_epoch)
            && !validator.slashed
            && self.state.previous_epoch_participation[index].has(flag)
    }
}
