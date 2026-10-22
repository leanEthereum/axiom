//! Voluntary exits and withdrawal credential changes, one per validator.

use std::collections::BTreeMap;

use axiom_types::{
    Epoch, ValidatorIndex, accessors::CoreState, capella::SignedBlsToExecutionChange,
    constants::BLS_WITHDRAWAL_PREFIX, phase0::SignedVoluntaryExit,
};

use crate::PoolError;

/// Signed requests of validators about their own lifecycle, waiting for a block.
///
/// # Overview
///
/// A validator exits once and changes its credentials once, so one request each suffices.
/// The first valid request stays; later ones for the same validator add nothing.
///
/// Entry checks what the state can refute without a signature.
/// The caller checked every signature, as gossip rules do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidatorRequests {
    /// Voluntary exits by validator.
    exits: BTreeMap<ValidatorIndex, SignedVoluntaryExit>,
    /// Credential changes by validator.
    credential_changes: BTreeMap<ValidatorIndex, SignedBlsToExecutionChange>,
}

impl ValidatorRequests {
    /// Adds a voluntary exit whose signature the caller verified.
    ///
    /// See `process_voluntary_exit` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the validator is unknown, inactive or exiting, or the exit's epoch is ahead.
    pub fn insert_exit<S: CoreState>(
        &mut self,
        state: &S,
        exit: SignedVoluntaryExit,
    ) -> Result<(), PoolError> {
        let message = &exit.message;
        let index = message.validator_index;
        let current = state.current_epoch();
        if message.epoch > current {
            return Err(PoolError::ExitInFuture {
                exit: message.epoch,
                current,
            });
        }
        if !Self::may_exit(state, index)? {
            return Err(PoolError::AlreadyInEffect(index));
        }
        self.exits.entry(index).or_insert(exit);
        Ok(())
    }

    /// Adds a credential change whose signature the caller verified.
    ///
    /// See `process_bls_to_execution_change` in the Capella beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the validator is unknown or no longer has BLS withdrawal credentials.
    pub fn insert_credential_change<S: CoreState>(
        &mut self,
        state: &S,
        change: SignedBlsToExecutionChange,
    ) -> Result<(), PoolError> {
        let index = change.message.validator_index;
        if !Self::has_bls_credentials(state, index)? {
            return Err(PoolError::NotBlsCredentials(index));
        }
        self.credential_changes.entry(index).or_insert(change);
        Ok(())
    }

    /// The exits, by increasing validator index.
    pub fn exits(&self) -> impl Iterator<Item = &SignedVoluntaryExit> {
        self.exits.values()
    }

    /// The credential changes, by increasing validator index.
    pub fn credential_changes(&self) -> impl Iterator<Item = &SignedBlsToExecutionChange> {
        self.credential_changes.values()
    }

    /// Drops requests the state already carried out.
    pub fn prune<S: CoreState>(&mut self, state: &S) {
        self.exits
            .retain(|index, _| Self::may_exit(state, *index).unwrap_or(false));
        self.credential_changes
            .retain(|index, _| Self::has_bls_credentials(state, *index).unwrap_or(false));
    }

    /// Whether a validator is active and not exiting yet.
    fn may_exit<S: CoreState>(state: &S, index: ValidatorIndex) -> Result<bool, PoolError> {
        let validators = state.validators();
        let validator = validators
            .get(index.as_usize())
            .ok_or(PoolError::UnknownValidator {
                index,
                registry_size: validators.len(),
            })?;
        Ok(validator.is_active_at(state.current_epoch())
            && validator.exit_epoch == Epoch::FAR_FUTURE)
    }

    /// Whether a validator still withdraws to BLS credentials.
    fn has_bls_credentials<S: CoreState>(
        state: &S,
        index: ValidatorIndex,
    ) -> Result<bool, PoolError> {
        let validators = state.validators();
        let validator = validators
            .get(index.as_usize())
            .ok_or(PoolError::UnknownValidator {
                index,
                registry_size: validators.len(),
            })?;
        Ok(validator.withdrawal_credentials.0[0] == BLS_WITHDRAWAL_PREFIX)
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        Bytes32, Minimal,
        capella::BlsToExecutionChange,
        phase0::{self, Validator, VoluntaryExit},
    };

    use super::*;

    /// A state at epoch 3 with two active validators: 0 with BLS credentials, 1 with 0x01 ones.
    fn state() -> phase0::BeaconState<Minimal> {
        let mut state = phase0::BeaconState::<Minimal>::default();
        state.slot = Epoch(3).start_slot::<Minimal>();
        for prefix in [0x00, 0x01] {
            let mut credentials = [0; 32];
            credentials[0] = prefix;
            let validator = Validator {
                withdrawal_credentials: Bytes32(credentials),
                exit_epoch: Epoch::FAR_FUTURE,
                withdrawable_epoch: Epoch::FAR_FUTURE,
                ..Validator::default()
            };
            state.validators.push(validator).unwrap();
        }
        state
    }

    fn exit(validator: u64, epoch: u64) -> SignedVoluntaryExit {
        SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: Epoch(epoch),
                validator_index: ValidatorIndex(validator),
            },
            ..SignedVoluntaryExit::default()
        }
    }

    #[test]
    fn the_first_exit_of_a_validator_stays() {
        let state = state();
        let mut requests = ValidatorRequests::default();
        requests.insert_exit(&state, exit(0, 2)).unwrap();
        requests.insert_exit(&state, exit(0, 3)).unwrap();

        assert_eq!(requests.exits().collect::<Vec<_>>(), [&exit(0, 2)]);
    }

    #[test]
    fn exits_ahead_of_time_or_already_under_way_are_refused() {
        let mut state = state();
        let mut requests = ValidatorRequests::default();
        // Epoch 4 lies ahead of the state's epoch 3.
        assert_eq!(
            requests.insert_exit(&state, exit(0, 4)),
            Err(PoolError::ExitInFuture {
                exit: Epoch(4),
                current: Epoch(3)
            })
        );
        // Mutation: validator 1 already exits at epoch 9.
        state.validators[1].exit_epoch = Epoch(9);
        assert_eq!(
            requests.insert_exit(&state, exit(1, 3)),
            Err(PoolError::AlreadyInEffect(ValidatorIndex(1)))
        );
        assert_eq!(
            requests.insert_exit(&state, exit(7, 3)),
            Err(PoolError::UnknownValidator {
                index: ValidatorIndex(7),
                registry_size: 2
            })
        );
    }

    #[test]
    fn a_credential_change_needs_bls_credentials_and_leaves_once_applied() {
        let mut state = state();
        let mut requests = ValidatorRequests::default();
        let change = |validator| SignedBlsToExecutionChange {
            message: BlsToExecutionChange {
                validator_index: ValidatorIndex(validator),
                ..BlsToExecutionChange::default()
            },
            ..SignedBlsToExecutionChange::default()
        };
        // Validator 1 already has 0x01 credentials.
        assert_eq!(
            requests.insert_credential_change(&state, change(1)),
            Err(PoolError::NotBlsCredentials(ValidatorIndex(1)))
        );
        requests
            .insert_credential_change(&state, change(0))
            .unwrap();

        // Mutation: a block applies the change to validator 0.
        state.validators[0].withdrawal_credentials.0[0] = 0x01;
        requests.prune(&state);
        assert_eq!(requests.credential_changes().count(), 0);
    }
}
