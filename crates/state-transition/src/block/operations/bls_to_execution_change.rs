//! Credential changes: moving withdrawals from a BLS key to an execution address.

use axiom_bls::PublicKey;
use axiom_types::{
    Domain, Preset, Root, SignedBlsToExecutionChange, SigningData,
    constants::{
        BLS_WITHDRAWAL_PREFIX, DOMAIN_BLS_TO_EXECUTION_CHANGE, ETH1_ADDRESS_WITHDRAWAL_PREFIX,
    },
};

use crate::{BlockError, BlockProcessor, Operation, StateError};

impl<P: Preset> Operation<P> for SignedBlsToExecutionChange {
    /// Rewrites BLS withdrawal credentials to point at an execution address.
    ///
    /// The old credentials commit to the withdrawal key by hash.
    /// The change must reveal that key and be signed by it.
    ///
    /// See `process_bls_to_execution_change` in the Capella beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        let change = &self.message;
        let state = &processor.state.beacon;
        let validator = state
            .validators
            .get(change.validator_index.as_usize())
            .ok_or(StateError::UnknownValidator(change.validator_index))?;

        let credentials = validator.withdrawal_credentials.0;
        if credentials[0] != BLS_WITHDRAWAL_PREFIX {
            return Err(BlockError::InvalidCredentialChange(
                "credentials are not BLS",
            ));
        }
        // Invariant: credentials = 0x00 || sha256(withdrawal key)[1..].
        if credentials[1..] != Root::sha256(&change.from_bls_pubkey.0).0[1..] {
            return Err(BlockError::InvalidCredentialChange(
                "key does not match credentials",
            ));
        }

        // Fork-agnostic domain, since a change stays valid across forks.
        let domain = Domain::compute(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            processor.config.genesis_fork_version,
            state.genesis_validators_root,
        );
        if processor.signatures.is_enabled() {
            let key = PublicKey::from_bytes(&change.from_bls_pubkey.0)
                .map_err(|_| BlockError::MalformedSignature)?;
            processor.verify_root(
                key,
                SigningData::signing_root(change, domain),
                &self.signature,
            )?;
        }

        let mut updated = [0; 32];
        updated[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX;
        updated[12..].copy_from_slice(&change.to_execution_address.0);
        processor.state.beacon.validators[change.validator_index.as_usize()]
            .withdrawal_credentials
            .0 = updated;
        Ok(())
    }
}
