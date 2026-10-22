//! The phase0 exit queue, which admits a number of validators per epoch.

use axiom_types::{Epoch, ValidatorIndex, accessors::CoreState};

use crate::{Fork, Registry, StateError};

/// The tail of the exit queue: its last scheduled epoch and how many exits it holds.
///
/// Each epoch admits a churn of validators, whatever their balances.
/// Electra replaced this with a churn of balance.
/// See `initiate_validator_exit` in the phase0 beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitQueue {
    /// The latest epoch an exit is scheduled for, or the earliest epoch allowed.
    tail: Epoch,
    /// Exits already scheduled for the tail epoch.
    tail_exits: u64,
    /// Exits each epoch admits.
    churn_limit: u64,
}

impl ExitQueue {
    /// Schedules a validator's exit at the back of the queue.
    ///
    /// A validator already exiting keeps its schedule.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist or an epoch overflows.
    pub fn initiate<S: Fork>(
        registry: &mut Registry<'_, S>,
        index: ValidatorIndex,
    ) -> Result<(), StateError> {
        let state = registry.state.beacon();
        let validators = state.validators();
        let validator = validators
            .get(index.as_usize())
            .ok_or(StateError::UnknownValidator {
                index,
                registry_size: validators.len(),
            })?;
        if validator.exit_epoch != Epoch::FAR_FUTURE {
            return Ok(());
        }
        let exit_epoch = Self::of(
            state,
            registry.config.min_per_epoch_churn_limit,
            registry.config.churn_limit_quotient,
        )
        .exit_epoch();
        let withdrawable_epoch = registry.withdrawable_epoch(exit_epoch)?;
        let validator = &mut registry.state.beacon.validators_mut()[index.as_usize()];
        validator.exit_epoch = exit_epoch;
        validator.withdrawable_epoch = withdrawable_epoch;
        Ok(())
    }

    /// The queue of a state, with the churn its active set allows.
    ///
    /// See `get_validator_churn_limit` in the phase0 beacon chain spec.
    fn of<S: CoreState + ?Sized>(state: &S, min_churn: u64, churn_quotient: u64) -> Self {
        let current = state.current_epoch();
        let validators = state.validators();
        let tail = validators
            .iter()
            .map(|validator| validator.exit_epoch)
            .filter(|epoch| *epoch != Epoch::FAR_FUTURE)
            .fold(current.activation_exit_epoch::<S::Preset>(), Epoch::max);
        let tail_exits = validators
            .iter()
            .filter(|validator| validator.exit_epoch == tail)
            .count() as u64;
        let active = validators
            .iter()
            .filter(|validator| validator.is_active_at(current))
            .count() as u64;
        Self {
            tail,
            tail_exits,
            churn_limit: min_churn.max(active / churn_quotient),
        }
    }

    /// The epoch the next exit lands in: the tail, or the epoch after a full tail.
    const fn exit_epoch(self) -> Epoch {
        if self.tail_exits >= self.churn_limit {
            Epoch(self.tail.0 + 1)
        } else {
            self.tail
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, phase0};

    use super::*;

    #[test]
    fn a_full_tail_pushes_the_exit_one_epoch_later() {
        // Fixture state: epoch 10 of the minimal preset, 4 active validators, one exiting at 15.
        let mut state = phase0::BeaconState::<Minimal> {
            slot: Epoch(10).start_slot::<Minimal>(),
            ..Default::default()
        };
        for exit_epoch in [
            Epoch(15),
            Epoch::FAR_FUTURE,
            Epoch::FAR_FUTURE,
            Epoch::FAR_FUTURE,
        ] {
            state
                .validators
                .push(phase0::Validator {
                    exit_epoch,
                    ..Default::default()
                })
                .unwrap();
        }

        // Churn: max(2, 4 / 32) = 2 exits per epoch; the tail at 15 holds one, so 15 has room.
        let queue = ExitQueue::of(&state, 2, 32);
        assert_eq!(queue.churn_limit, 2);
        assert_eq!(queue.exit_epoch(), Epoch(15));

        // With a churn of one, the tail is full, so the next exit lands at 16.
        let queue = ExitQueue::of(&state, 1, 32);
        assert_eq!(queue.exit_epoch(), Epoch(16));
    }
}
