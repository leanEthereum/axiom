//! Key authorization requests: a withdrawal address naming the keys its validator may register.

use axiom_types::{
    Epoch, Preset,
    accessors::PqRegistryState,
    hstar::{PendingPqKeyAuthorization, PqKeyAuthorizationRequest},
};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

impl<S: Fork + PqRegistryState> Operation<S> for PqKeyAuthorizationRequest {
    /// Records a withdrawal address's authorization of keys, replacing any pending one.
    ///
    /// A request that breaks a rule is ignored rather than invalidating the block.
    /// The execution layer cannot know the beacon state, so it relays every request it sees.
    ///
    /// The authorization is usable through the epoch PQ_KEY_AUTHORIZATION_EXPIRY epochs ahead.
    /// See `process_pq_key_authorization_request` in EIP-8450.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        // The validator, named by its BLS key; an unknown key is ignored.
        let Some(index) = processor.state.validator_index(&self.validator_pubkey) else {
            return Ok(());
        };
        let state = &mut *processor.state.beacon;
        let validators = state.validators();
        let validator = validators
            .get(index.as_usize())
            .ok_or(StateError::UnknownValidator {
                index,
                registry_size: validators.len(),
            })?;

        // Only the validator's own withdrawal address may authorize, and only before any exit.
        if !validator.has_execution_withdrawal_credential()
            || validator.withdrawal_address() != self.source_address
            || validator.exit_epoch != Epoch::FAR_FUTURE
        {
            return Ok(());
        }

        // A newer authorization replaces the pending one, so a validator has at most one.
        if let Some(position) = state.pq_key_authorization_position(index) {
            state
                .pending_pq_key_authorizations_mut()
                .drain(position..=position);
        }

        let expiry_epoch = state
            .current_epoch()
            .checked_add(S::Preset::PQ_KEY_AUTHORIZATION_EXPIRY.0)
            .ok_or(StateError::Overflow {
                quantity: "key authorization expiry epoch",
            })?;
        state
            .pending_pq_key_authorizations_mut()
            .push(PendingPqKeyAuthorization {
                validator_index: index,
                source_address: self.source_address,
                public_keys_root: self.public_keys_root,
                expiry_epoch,
            });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Ssz;
    use axiom_types::{
        BlsPubkey, ExecutionAddress, Minimal, Root, ValidatorIndex, accessors::CoreState,
        hstar::BeaconState,
    };

    use super::*;
    use crate::hstar::block::fixture::{self, EPOCH, apply, keys, state};

    /// Validator `index`'s authorization of key 0, from its own withdrawal address.
    fn request(state: &BeaconState<Minimal>, index: u64) -> PqKeyAuthorizationRequest {
        PqKeyAuthorizationRequest {
            source_address: fixture::withdrawal_address(index),
            validator_pubkey: state.validators()[index as usize].pubkey,
            public_keys_root: keys(0).hash_tree_root(),
        }
    }

    #[test]
    fn a_request_is_usable_for_256_epochs() {
        // Fixture state: epoch 5, an empty queue.
        let mut state = state();

        let operation = request(&state, 1);

        apply(&mut state, &operation).unwrap();

        // Timing: usable through epoch 5 + 256 = 261, see PQ_KEY_AUTHORIZATION_EXPIRY.
        assert_eq!(
            state.pending_pq_key_authorizations.to_vec(),
            [PendingPqKeyAuthorization {
                validator_index: ValidatorIndex(1),
                source_address: fixture::withdrawal_address(1),
                public_keys_root: keys(0).hash_tree_root(),
                expiry_epoch: Epoch(EPOCH.0 + 256),
            }]
        );
    }

    #[test]
    fn a_newer_request_replaces_the_pending_one() {
        // Fixture state: validator 1 authorized key 0, then validator 2 authorized key 0.
        let mut state = state();
        let operation = request(&state, 1);
        apply(&mut state, &operation).unwrap();
        let operation = request(&state, 2);
        apply(&mut state, &operation).unwrap();

        // Validator 1 now authorizes the root 0x05..05 instead.
        let newer = PqKeyAuthorizationRequest {
            public_keys_root: Root([5; 32]),
            ..request(&state, 1)
        };
        apply(&mut state, &newer).unwrap();

        // One entry per validator: validator 2's stays, validator 1's moves to the back.
        let queue: Vec<(ValidatorIndex, Root)> = state
            .pending_pq_key_authorizations
            .iter()
            .map(|entry| (entry.validator_index, entry.public_keys_root))
            .collect();
        assert_eq!(
            queue,
            [
                (ValidatorIndex(2), keys(0).hash_tree_root()),
                (ValidatorIndex(1), Root([5; 32])),
            ]
        );
    }

    #[test]
    fn invalid_requests_are_ignored_without_failing_the_block() {
        // Each mutation breaks one rule; the request is skipped and the queue stays empty.
        let mut exiting = state();
        exiting.validators.get_mut(1).unwrap().exit_epoch = Epoch(9);
        let mut bls_credentials = state();
        bls_credentials
            .validators
            .get_mut(1)
            .unwrap()
            .withdrawal_credentials
            .0[0] = 0x00;
        let unknown_key = PqKeyAuthorizationRequest {
            validator_pubkey: BlsPubkey([0xaa; 48]),
            ..request(&state(), 1)
        };
        let foreign_source = PqKeyAuthorizationRequest {
            source_address: ExecutionAddress([0x99; 20]),
            ..request(&state(), 1)
        };
        let cases = [
            ("unknown validator key", state(), unknown_key),
            ("another address", state(), foreign_source),
            ("BLS credentials", bls_credentials, request(&state(), 1)),
            ("exiting validator", exiting, request(&state(), 1)),
        ];

        for (case, mut state, request) in cases {
            assert_eq!(apply(&mut state, &request), Ok(()), "{case}");
            assert!(state.pending_pq_key_authorizations.is_empty(), "{case}");
        }
    }
}
