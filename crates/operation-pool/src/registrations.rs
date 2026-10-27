//! Post-quantum key registrations waiting for a block, one per validator.

use std::collections::BTreeMap;

use axiom_types::{
    Epoch, ValidatorIndex,
    accessors::{CoreState, PqRegistryState},
    hstar::SignedPqKeyRegistration,
};

use crate::PoolError;

/// Signed key registrations, by validator, waiting for a block.
///
/// # Overview
///
/// A block registers at most one key per validator, so one registration each suffices.
/// A newer registration replaces an older one for the same validator.
/// Gossip already keeps only the first operator-path registration, see EIP-8450.
/// A later one reaching the pool then comes from the owner path, which may replace keys.
///
/// Entry checks what the state can refute without a signature.
/// The caller verified the BLS authorization and the proof of possession, as gossip does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegistrationPool {
    /// Registrations by validator.
    registrations: BTreeMap<ValidatorIndex, SignedPqKeyRegistration>,
}

impl RegistrationPool {
    /// Adds a registration whose signatures the caller verified.
    ///
    /// # Errors
    ///
    /// Fails when the validator is unknown or has initiated an exit.
    pub fn insert<S: CoreState>(
        &mut self,
        state: &S,
        registration: SignedPqKeyRegistration,
    ) -> Result<(), PoolError> {
        let index = registration.message.validator_index;
        if !Self::may_register(state, index)? {
            return Err(PoolError::AlreadyInEffect(index));
        }
        self.registrations.insert(index, registration);
        Ok(())
    }

    /// The registrations, by increasing validator index.
    pub fn iter(&self) -> impl Iterator<Item = &SignedPqKeyRegistration> {
        self.registrations.values()
    }

    /// Drops the registrations the state already holds, and those of exiting validators.
    pub fn prune<S: PqRegistryState + ?Sized>(&mut self, state: &S) {
        let keys = state.pq_public_keys();
        self.registrations.retain(|index, registration| {
            let applied = keys.get(index.as_usize()) == Some(&registration.message.public_keys);
            !applied && Self::may_register(state, *index).unwrap_or(false)
        });
    }

    /// Whether a validator can still register: it exists and has not initiated an exit.
    fn may_register<S: CoreState + ?Sized>(
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
        Ok(validator.exit_epoch == Epoch::FAR_FUTURE)
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        Gwei, Minimal, XmssPublicKey,
        constants::PQ_KEYS_VERSION_1,
        hstar::{self, PqKeyRegistration, PqPublicKeys},
        phase0::Validator,
    };

    use super::*;

    /// An Hstar state with two validators: 0 active, 1 exiting at epoch 5.
    fn state() -> hstar::BeaconState<Minimal> {
        let mut state = hstar::BeaconState::<Minimal>::default();
        for exit_epoch in [Epoch::FAR_FUTURE, Epoch(5)] {
            let validator = Validator {
                exit_epoch,
                ..Validator::default()
            };
            state
                .push_validator(validator, Gwei(32_000_000_000))
                .unwrap();
        }
        state
    }

    /// A registration of validator `index` for the key whose bytes all equal `byte`.
    fn registration(index: u64, byte: u8) -> SignedPqKeyRegistration {
        SignedPqKeyRegistration {
            message: PqKeyRegistration {
                validator_index: ValidatorIndex(index),
                public_keys: PqPublicKeys {
                    version: PQ_KEYS_VERSION_1,
                    xmss_public_key: XmssPublicKey([byte; 32]),
                },
            },
            ..SignedPqKeyRegistration::default()
        }
    }

    #[test]
    fn a_newer_registration_replaces_the_older() {
        // Fixture state: validator 0 registers key 0x01, then key 0x02.
        let state = state();
        let mut pool = RegistrationPool::default();
        pool.insert(&state, registration(0, 1)).unwrap();
        pool.insert(&state, registration(0, 2)).unwrap();

        // One registration per validator: the second.
        assert_eq!(
            pool.iter().cloned().collect::<Vec<_>>(),
            [registration(0, 2)]
        );
    }

    #[test]
    fn unknown_and_exiting_validators_are_refused() {
        let state = state();
        let mut pool = RegistrationPool::default();

        // Validator 1 exits at epoch 5, so it may no longer register.
        assert_eq!(
            pool.insert(&state, registration(1, 1)),
            Err(PoolError::AlreadyInEffect(ValidatorIndex(1)))
        );

        // Validator 2 does not exist in a registry of 2.
        assert_eq!(
            pool.insert(&state, registration(2, 1)),
            Err(PoolError::UnknownValidator {
                index: ValidatorIndex(2),
                registry_size: 2,
            })
        );
    }

    #[test]
    fn a_registration_leaves_once_the_state_holds_its_key() {
        // Fixture state: validator 0 waits with key 0x01.
        let mut state = state();
        let mut pool = RegistrationPool::default();
        pool.insert(&state, registration(0, 1)).unwrap();

        // A finalized state with another key keeps the registration waiting.
        *state.pq_public_keys_mut().get_mut(0).unwrap() = registration(0, 9).message.public_keys;
        pool.prune(&state);
        assert_eq!(pool.iter().count(), 1);

        // Once the state holds key 0x01, the registration is done.
        *state.pq_public_keys_mut().get_mut(0).unwrap() = registration(0, 1).message.public_keys;
        pool.prune(&state);
        assert_eq!(pool.iter().count(), 0);
    }
}
