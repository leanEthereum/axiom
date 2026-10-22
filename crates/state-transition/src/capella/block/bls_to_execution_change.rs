//! Credential changes: moving withdrawals from a BLS key to an execution address.

use axiom_bls::PublicKey;
use axiom_types::{
    Domain, Root,
    capella::SignedBlsToExecutionChange,
    constants::{
        BLS_WITHDRAWAL_PREFIX, DOMAIN_BLS_TO_EXECUTION_CHANGE, ETH1_ADDRESS_WITHDRAWAL_PREFIX,
    },
    phase0::SigningData,
};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

impl<S: Fork> Operation<S> for SignedBlsToExecutionChange {
    /// Rewrites BLS withdrawal credentials to point at an execution address.
    ///
    /// The old credentials commit to the withdrawal key by hash.
    /// The change must reveal that key and be signed by it.
    ///
    /// No fork changed this step.
    /// See `process_bls_to_execution_change` in the Capella beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let change = &self.message;
        let state = processor.state.beacon();
        let validators = state.validators();
        let validator = validators.get(change.validator_index.as_usize()).ok_or(
            StateError::UnknownValidator {
                index: change.validator_index,
                registry_size: validators.len(),
            },
        )?;
        let invalid = |reason| BlockError::InvalidCredentialChange {
            validator: change.validator_index,
            reason,
        };

        let credentials = validator.withdrawal_credentials.0;
        if credentials[0] != BLS_WITHDRAWAL_PREFIX {
            return Err(invalid("credentials are not BLS"));
        }
        // Invariant: credentials = 0x00 || sha256(withdrawal key)[1..].
        if credentials[1..] != Root::sha256(&change.from_bls_pubkey.0).0[1..] {
            return Err(invalid("key does not match credentials"));
        }

        // Fork-agnostic domain, since a change stays valid across forks.
        let domain = Domain::compute(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            processor.config.genesis_fork_version,
            state.genesis_validators_root(),
        );
        if processor.checks_signatures() {
            let key = PublicKey::from_bytes(&change.from_bls_pubkey.0)
                .map_err(|_| invalid("withdrawal key does not decompress"))?;
            processor.verify_root(
                key,
                SigningData::signing_root(change, domain),
                &self.signature,
            )?;
        }

        let mut updated = [0; 32];
        updated[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX;
        updated[12..].copy_from_slice(&change.to_execution_address.0);
        processor.state.beacon.validators_mut()[change.validator_index.as_usize()]
            .withdrawal_credentials
            .0 = updated;
        Ok(())
    }
}
