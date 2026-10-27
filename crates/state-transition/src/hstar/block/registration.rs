//! Post-quantum key registrations: a validator's leanXMSS key entering the registry.

use axiom_ssz::Ssz;
use axiom_types::{
    ChainConfig, Domain, Epoch, ExecutionAddress, Root, ValidatorIndex, XmssLeafIndex,
    accessors::PqRegistryState,
    constants::{
        DOMAIN_PQ_KEY_POSSESSION, DOMAIN_PQ_KEY_REGISTRATION, G2_POINT_AT_INFINITY,
        PQ_KEYS_VERSION_1, PQ_POSSESSION_XMSS_INDEX,
    },
    hstar::{PqKeyRegistration, SignedPqKeyRegistration, XmssSignature},
    phase0::{SigningData, Validator},
};
use lean_pq::{
    Error as LeanPqError,
    xmss::{PublicKey as XmssKey, Signature as XmssProof},
};
use thiserror::Error;

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

/// Why a key registration is invalid, which invalidates its block.
///
/// Each variant names the assertion of `process_pq_key_registration` that failed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RegistrationError {
    /// The validator has initiated an exit, so it can no longer register.
    #[error("validator exits at epoch {0}")]
    Exiting(Epoch),
    /// The key's version names no verifier this fork knows.
    #[error("key version {0} is not a known parameter set")]
    UnsupportedVersion(u8),
    /// The owner path found no pending authorization for the validator.
    #[error("no withdrawal address authorized keys for the validator")]
    NoAuthorization,
    /// The pending authorization is for other keys.
    #[error("authorized keys have root {authorized}, the registration's have root {actual}")]
    AuthorizationRootMismatch {
        /// Root the withdrawal address authorized.
        authorized: Root,
        /// Root of the keys the registration carries.
        actual: Root,
    },
    /// The pending authorization expired before this epoch.
    #[error("authorization expired at epoch {expiry}, the current epoch is {current}")]
    AuthorizationExpired {
        /// Last epoch the authorization could be used in.
        expiry: Epoch,
        /// The state's epoch.
        current: Epoch,
    },
    /// The validator's withdrawal credentials name no execution address.
    #[error("withdrawal credentials have prefix {0:#04x}, not an execution address")]
    NoExecutionAddress(u8),
    /// The authorization comes from another address than the validator's withdrawal address.
    #[error("authorized by {source_address}, the withdrawal address is {withdrawal_address}")]
    SourceAddressMismatch {
        /// Address that made the authorization.
        source_address: ExecutionAddress,
        /// The validator's withdrawal address.
        withdrawal_address: ExecutionAddress,
    },
    /// The operator path cannot replace keys once registered.
    #[error("keys are already registered, and only the withdrawal address may replace them")]
    AlreadyRegistered,
    /// Another validator registered the same key.
    #[error("the key is already registered by validator {0}")]
    KeyInUse(ValidatorIndex),
    /// The proof of possession is signed at a leaf other than the reserved one.
    #[error("proof of possession at leaf {actual}, the reserved leaf is {expected}")]
    PossessionLeafIndex {
        /// The reserved leaf index.
        expected: XmssLeafIndex,
        /// The leaf index the proof uses.
        actual: XmssLeafIndex,
    },
    /// The proof of possession does not verify under the registered key.
    ///
    /// The binding's error is boxed: inline, it would set the size of every block error.
    #[error("proof of possession: {0}")]
    InvalidPossession(#[source] Box<LeanPqError>),
}

impl<S: Fork + PqRegistryState> Operation<S> for SignedPqKeyRegistration {
    /// Registers or replaces one validator's post-quantum key.
    ///
    /// The BLS field selects the authority, see EIP-8450:
    ///
    /// - The point at infinity: the withdrawal address authorized the keys on the execution layer.
    ///   This owner path may register or replace keys.
    /// - A BLS signature: the validator's signing key authorized them.
    ///   This operator path only registers, since a quantum adversary may forge BLS signatures.
    ///
    /// Both paths then require a key no other validator holds, and a valid proof of possession.
    /// See `process_pq_key_registration` in EIP-8450.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let registration = &self.message;
        let index = registration.validator_index;
        let keys = registration.public_keys;
        let invalid = |reason| BlockError::InvalidPqKeyRegistration {
            validator: index,
            reason,
        };

        // Phase 1: the validator exists, has not started to exit, and the key has a known version.
        let state = processor.state.beacon();
        let validators = state.validators();
        let validator = validators
            .get(index.as_usize())
            .ok_or(StateError::UnknownValidator {
                index,
                registry_size: validators.len(),
            })?
            .clone();
        if validator.exit_epoch != Epoch::FAR_FUTURE {
            return Err(invalid(RegistrationError::Exiting(validator.exit_epoch)));
        }
        if keys.version != PQ_KEYS_VERSION_1 {
            return Err(invalid(RegistrationError::UnsupportedVersion(keys.version)));
        }

        // Phase 2: the authority, by the path the BLS field selects.
        let genesis_validators_root = state.genesis_validators_root();
        if self.signature == G2_POINT_AT_INFINITY {
            OwnerAuthorization::consume(processor, registration, &validator).map_err(invalid)?;
        } else {
            if processor.state.beacon().is_pq_registered(index) {
                return Err(invalid(RegistrationError::AlreadyRegistered));
            }
            // The BLS signature joins the block's batch, like every other operation's.
            let domain = Domain::compute(
                DOMAIN_PQ_KEY_REGISTRATION,
                processor.config.genesis_fork_version,
                genesis_validators_root,
            );
            processor.verify_signature(index, registration, domain, &self.signature)?;
        }

        // Phase 3: a key held by no other validator.
        // Invariant: signed messages never name their validator, so one key must serve one index.
        // Otherwise a validator could claim another's signatures as its own participation.
        let state = processor.state.beacon();
        if let Some(holder) = state.pq_public_key_holder(&keys.xmss_public_key, index) {
            return Err(invalid(RegistrationError::KeyInUse(holder)));
        }

        // Phase 4: the registrant holds the secret key, and signed this very registration.
        let proof = PossessionProof::new(registration, &self.possession);
        proof.check_leaf_index().map_err(invalid)?;
        if processor.checks_signatures() {
            let root = proof.signing_root(processor.config, genesis_validators_root);
            proof.verify(root).map_err(invalid)?;
        }

        // Phase 5: the key takes the validator's entry.
        if let Some(entry) = processor
            .state
            .beacon
            .pq_public_keys_mut()
            .get_mut(index.as_usize())
        {
            *entry = keys;
        }
        Ok(())
    }
}

/// The owner path: a withdrawal address's pending authorization of exactly these keys.
///
/// The withdrawal address already controls the stake, and can exit the validator, see EIP-7002.
/// Letting it replace keys therefore gives it no new power.
#[derive(Clone, Copy, Debug)]
struct OwnerAuthorization;

impl OwnerAuthorization {
    /// Checks the validator's pending authorization against the registration, then removes it.
    ///
    /// The checks run in the order EIP-8450 lists them, so the first broken one is reported.
    fn consume<S: Fork + PqRegistryState>(
        processor: &mut BlockProcessor<'_, S>,
        registration: &PqKeyRegistration,
        validator: &Validator,
    ) -> Result<(), RegistrationError> {
        let state = &mut *processor.state.beacon;
        let current = state.current_epoch();
        let position = state
            .pq_key_authorization_position(registration.validator_index)
            .ok_or(RegistrationError::NoAuthorization)?;
        let authorization = state.pending_pq_key_authorizations()[position];

        // The withdrawal address committed to the keys by root.
        let actual = registration.public_keys.hash_tree_root();
        if authorization.public_keys_root != actual {
            return Err(RegistrationError::AuthorizationRootMismatch {
                authorized: authorization.public_keys_root,
                actual,
            });
        }
        if authorization.expiry_epoch < current {
            return Err(RegistrationError::AuthorizationExpired {
                expiry: authorization.expiry_epoch,
                current,
            });
        }

        // The authorization must come from this validator's own withdrawal address.
        if !validator.has_execution_withdrawal_credential() {
            return Err(RegistrationError::NoExecutionAddress(
                validator.withdrawal_credentials.0[0],
            ));
        }
        let withdrawal_address = validator.withdrawal_address();
        if withdrawal_address != authorization.source_address {
            return Err(RegistrationError::SourceAddressMismatch {
                source_address: authorization.source_address,
                withdrawal_address,
            });
        }

        // The authorization is spent, keeping the order of the others.
        // See `remove_pq_key_authorization` in EIP-8450.
        state
            .pending_pq_key_authorizations_mut()
            .drain(position..=position);
        Ok(())
    }
}

/// A registration's proof of possession: the registered key's signature of the registration.
///
/// # Overview
///
/// The proof detects a key that does not match its seed, at registration rather than at the switch.
/// It signs the validator index, so a copied key cannot be registered for another validator.
/// That prevents both key copying and squatting on a key published but not yet registered.
///
/// Every input is public, so verification has no constant-time requirement.
/// See `is_valid_pq_possession_proof` in EIP-8450.
#[derive(Clone, Copy, Debug)]
pub struct PossessionProof<'a> {
    /// The registration the proof signs.
    registration: &'a PqKeyRegistration,
    /// The leanXMSS signature.
    signature: &'a XmssSignature,
}

impl<'a> PossessionProof<'a> {
    /// A proof of a registration.
    #[must_use]
    pub const fn new(registration: &'a PqKeyRegistration, signature: &'a XmssSignature) -> Self {
        Self {
            registration,
            signature,
        }
    }

    /// Checks that the proof is signed at the leaf index reserved for it.
    ///
    /// A signer signs nothing else at that leaf, so the proof never reuses a duty's one-time key.
    ///
    /// # Errors
    ///
    /// Fails when the proof uses another leaf index.
    pub fn check_leaf_index(self) -> Result<(), RegistrationError> {
        let actual = self.signature.leaf_index;
        if actual != PQ_POSSESSION_XMSS_INDEX {
            return Err(RegistrationError::PossessionLeafIndex {
                expected: PQ_POSSESSION_XMSS_INDEX,
                actual,
            });
        }
        Ok(())
    }

    /// The message the proof signs: the registration, under the genesis fork version.
    ///
    /// The genesis version keeps a registration valid across forks, as for credential changes.
    /// See `get_pq_possession_signing_root` in EIP-8450.
    #[must_use]
    pub fn signing_root(self, config: &ChainConfig, genesis_validators_root: Root) -> Root {
        let domain = Domain::compute(
            DOMAIN_PQ_KEY_POSSESSION,
            config.genesis_fork_version,
            genesis_validators_root,
        );
        SigningData::signing_root(self.registration, domain)
    }

    /// Verifies the leanXMSS signature of a signing root under the registered key.
    ///
    /// The container's SSZ encoding is exactly leanXMSS's 2404-byte signature encoding.
    /// The 32-byte key is likewise the scheme's own encoding, so neither needs translating.
    ///
    /// # Errors
    ///
    /// Fails when the signature does not verify.
    pub fn verify(self, signing_root: Root) -> Result<(), RegistrationError> {
        let invalid = |error| RegistrationError::InvalidPossession(Box::new(error));
        let key = XmssKey::from_bytes(self.registration.public_keys.xmss_public_key.as_bytes())
            .map_err(invalid)?;
        let signature = XmssProof::from_bytes(&self.signature.encode()).map_err(invalid)?;
        key.verify(&signing_root.0, &signature).map_err(invalid)
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        Epoch, ExecutionAddress, ValidatorIndex, XmssLeafIndex,
        hstar::{PendingPqKeyAuthorization, PqPublicKeys},
    };

    use super::*;
    use crate::hstar::block::fixture::{
        self, EPOCH, VALIDATORS, apply, keys, operator_signed, possession, registration, state,
    };

    /// The error a registration of validator 0 fails with, for a reason.
    const fn refused(reason: RegistrationError) -> BlockError {
        BlockError::InvalidPqKeyRegistration {
            validator: ValidatorIndex(0),
            reason,
        }
    }

    /// A pending authorization of keys by validator 0's own withdrawal address.
    fn authorization(keys: &PqPublicKeys, expiry_epoch: Epoch) -> PendingPqKeyAuthorization {
        PendingPqKeyAuthorization {
            validator_index: ValidatorIndex(0),
            source_address: fixture::withdrawal_address(0),
            public_keys_root: keys.hash_tree_root(),
            expiry_epoch,
        }
    }

    #[test]
    fn the_operator_path_registers_a_validator_without_keys() {
        // Fixture state: four validators, none registered.
        let mut state = state();
        let signed = operator_signed(&state, registration(&state, 0, 0));

        // The BLS signature and the proof of possession both verify.
        apply(&mut state, &signed).unwrap();

        // Validator 0 now holds key 0; the others keep the unset entry.
        assert_eq!(state.pq_public_keys[0], keys(0));
        assert!(
            state
                .pq_public_keys
                .iter()
                .skip(1)
                .all(|entry| !entry.is_registered())
        );
    }

    #[test]
    fn the_operator_path_cannot_replace_keys() {
        // Fixture state: validator 0 already holds key 1.
        //
        // A forged BLS signature must not move a key once registered.
        // So the operator path only ever registers, see EIP-8450.
        let mut state = state();
        *state.pq_public_keys.get_mut(0).unwrap() = keys(1);
        let signed = operator_signed(&state, registration(&state, 0, 0));

        assert_eq!(
            apply(&mut state, &signed),
            Err(refused(RegistrationError::AlreadyRegistered))
        );
    }

    #[test]
    fn the_operator_signature_must_be_the_validators() {
        // Mutation: validator 1's BLS key signs validator 0's registration.
        let mut state = state();
        let mut signed = operator_signed(&state, registration(&state, 1, 0));
        signed.message.validator_index = ValidatorIndex(0);
        signed.possession = possession(&state, &signed.message, 0, XmssLeafIndex(0));

        // The block's batch of one signature fails as a whole.
        assert_eq!(
            apply(&mut state, &signed),
            Err(BlockError::InvalidSignature { signatures: 1 })
        );
    }

    #[test]
    fn the_owner_path_consumes_its_authorization_and_replaces_keys() {
        // Fixture state: validator 0 holds key 1.
        // Its withdrawal address authorized key 0, through epoch 5.
        // Validator 2 also waits on an authorization, behind it in the queue.
        let mut state = state();
        *state.pq_public_keys.get_mut(0).unwrap() = keys(1);
        let other = PendingPqKeyAuthorization {
            validator_index: ValidatorIndex(2),
            ..authorization(&keys(0), EPOCH)
        };
        state
            .pending_pq_key_authorizations
            .push(authorization(&keys(0), EPOCH));
        state.pending_pq_key_authorizations.push(other);

        // The point at infinity selects the owner path.
        let operation = registration(&state, 0, 0);
        apply(&mut state, &operation).unwrap();

        // Key 0 replaces key 1, and only validator 2's authorization remains.
        assert_eq!(state.pq_public_keys[0], keys(0));
        assert_eq!(state.pending_pq_key_authorizations.to_vec(), [other]);
    }

    #[test]
    fn a_validator_may_register_its_own_current_key_again() {
        // Fixture state: validator 0 holds key 0, and its owner authorized key 0 once more.
        //
        // The uniqueness check skips the registering validator, so this is no collision.
        let mut state = state();
        *state.pq_public_keys.get_mut(0).unwrap() = keys(0);
        state
            .pending_pq_key_authorizations
            .push(authorization(&keys(0), EPOCH));

        let operation = registration(&state, 0, 0);

        apply(&mut state, &operation).unwrap();

        assert_eq!(state.pq_public_keys[0], keys(0));
        assert!(state.pending_pq_key_authorizations.is_empty());
    }

    #[test]
    fn the_owner_path_needs_an_authorization() {
        // Fixture state: the queue is empty, so the owner never paid for an authorization.
        let mut state = state();

        let operation = registration(&state, 0, 0);

        assert_eq!(
            apply(&mut state, &operation),
            Err(refused(RegistrationError::NoAuthorization))
        );
    }

    #[test]
    fn the_owner_path_needs_the_authorized_keys() {
        // Fixture state: the owner authorized key 1, but the registration carries key 0.
        let mut state = state();
        state
            .pending_pq_key_authorizations
            .push(authorization(&keys(1), EPOCH));

        let operation = registration(&state, 0, 0);

        assert_eq!(
            apply(&mut state, &operation),
            Err(refused(RegistrationError::AuthorizationRootMismatch {
                authorized: keys(1).hash_tree_root(),
                actual: keys(0).hash_tree_root(),
            }))
        );
    }

    #[test]
    fn the_owner_path_needs_an_unexpired_authorization() {
        // Timing: the authorization was usable through epoch 4; the state is at epoch 5.
        let mut state = state();
        state
            .pending_pq_key_authorizations
            .push(authorization(&keys(0), Epoch(4)));

        let operation = registration(&state, 0, 0);

        assert_eq!(
            apply(&mut state, &operation),
            Err(refused(RegistrationError::AuthorizationExpired {
                expiry: Epoch(4),
                current: EPOCH,
            }))
        );
    }

    #[test]
    fn the_owner_path_needs_an_execution_withdrawal_address() {
        // Mutation: validator 0 still withdraws to BLS credentials, prefix 0x00.
        let mut state = state();
        state
            .validators
            .get_mut(0)
            .unwrap()
            .withdrawal_credentials
            .0[0] = 0x00;
        state
            .pending_pq_key_authorizations
            .push(authorization(&keys(0), EPOCH));

        let operation = registration(&state, 0, 0);

        assert_eq!(
            apply(&mut state, &operation),
            Err(refused(RegistrationError::NoExecutionAddress(0x00)))
        );
    }

    #[test]
    fn the_owner_path_needs_the_validators_own_address() {
        // Mutation: the authorization came from address 0x99..99, not validator 0's 0x10..10.
        let mut state = state();
        let foreign = ExecutionAddress([0x99; 20]);
        state
            .pending_pq_key_authorizations
            .push(PendingPqKeyAuthorization {
                source_address: foreign,
                ..authorization(&keys(0), EPOCH)
            });

        let operation = registration(&state, 0, 0);

        assert_eq!(
            apply(&mut state, &operation),
            Err(refused(RegistrationError::SourceAddressMismatch {
                source_address: foreign,
                withdrawal_address: fixture::withdrawal_address(0),
            }))
        );
    }

    #[test]
    fn an_exiting_validator_cannot_register() {
        // Mutation: validator 0 initiated an exit, effective at epoch 9.
        let mut state = state();
        state.validators.get_mut(0).unwrap().exit_epoch = Epoch(9);
        let signed = operator_signed(&state, registration(&state, 0, 0));

        assert_eq!(
            apply(&mut state, &signed),
            Err(refused(RegistrationError::Exiting(Epoch(9))))
        );
    }

    #[test]
    fn an_unknown_version_is_refused_before_any_signature() {
        // Mutation: version 2 names no parameter set; no signature is needed to refuse it.
        let mut state = state();
        let mut signed = registration(&state, 0, 0);
        signed.message.public_keys.version = 2;

        assert_eq!(
            apply(&mut state, &signed),
            Err(refused(RegistrationError::UnsupportedVersion(2)))
        );
    }

    #[test]
    fn an_unknown_validator_breaks_the_state_bound() {
        // The registry holds 4 validators, so index 4 is one past its end.
        let mut state = state();
        let mut signed = registration(&state, 0, 0);
        signed.message.validator_index = ValidatorIndex(VALIDATORS);

        assert_eq!(
            apply(&mut state, &signed),
            Err(StateError::UnknownValidator {
                index: ValidatorIndex(VALIDATORS),
                registry_size: VALIDATORS as usize,
            }
            .into())
        );
    }

    #[test]
    fn a_key_held_by_another_validator_is_refused() {
        // Fixture state: validator 1 holds key 0.
        //
        // Signed messages never name their validator.
        // A shared key would let validator 0 claim validator 1's votes as its own.
        let mut state = state();
        *state.pq_public_keys.get_mut(1).unwrap() = keys(0);
        let signed = operator_signed(&state, registration(&state, 0, 0));

        assert_eq!(
            apply(&mut state, &signed),
            Err(refused(RegistrationError::KeyInUse(ValidatorIndex(1))))
        );
    }

    #[test]
    fn the_proof_must_use_the_reserved_leaf() {
        // Mutation: the proof is a valid signature, but at leaf 1, which a duty may use.
        let mut state = state();
        let mut signed = registration(&state, 0, 0);
        signed.possession = possession(&state, &signed.message, 0, XmssLeafIndex(1));
        let signed = operator_signed(&state, signed);

        assert_eq!(
            apply(&mut state, &signed),
            Err(refused(RegistrationError::PossessionLeafIndex {
                expected: XmssLeafIndex(0),
                actual: XmssLeafIndex(1),
            }))
        );
    }

    #[test]
    fn a_copied_proof_does_not_register_another_validator() {
        // Squatting: the proof signs validator 1's registration of key 0.
        // An attacker submits it for validator 0, which the proof does not name.
        let mut state = state();
        let theirs = registration(&state, 1, 0);
        let mut squatted = registration(&state, 0, 0);
        squatted.possession = theirs.possession;
        let squatted = operator_signed(&state, squatted);

        // The binding rejects the proof for the message validator 0 would have signed.
        let root = PossessionProof::new(&squatted.message, &squatted.possession)
            .signing_root(&fixture::config(), state.genesis_validators_root);
        let expected = XmssKey::from_bytes(keys(0).xmss_public_key.as_bytes())
            .unwrap()
            .verify(
                &root.0,
                &XmssProof::from_bytes(&squatted.possession.encode()).unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            apply(&mut state, &squatted),
            Err(refused(RegistrationError::InvalidPossession(Box::new(
                expected
            ))))
        );
    }
}
