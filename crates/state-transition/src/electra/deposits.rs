//! Deposits that cleared the queue: top-ups and new validators.

use axiom_bls::{PublicKey, Signature};
use axiom_types::{
    ChainConfig, Domain, Root,
    accessors::ParticipationState,
    constants::DOMAIN_DEPOSIT,
    electra::PendingDeposit,
    phase0::{DepositMessage, SigningData, Validator},
};

use crate::{CachedState, StateError, Verification};

/// A pending deposit whose turn came: it tops up a validator, or creates one.
///
/// See `apply_pending_deposit` in the Electra beacon chain spec.
#[derive(Clone, Copy, Debug)]
pub struct DepositApplication<'a>(pub &'a PendingDeposit);

impl DepositApplication<'_> {
    /// Applies the deposit.
    ///
    /// A deposit for a new key must carry a proof of possession.
    /// Otherwise one key holder could register a key derived from another's, a rogue key attack.
    ///
    /// # Errors
    ///
    /// Fails when a list is full or a balance overflows.
    pub fn apply<S: ParticipationState>(
        self,
        state: &mut CachedState<'_, S>,
        config: &ChainConfig,
    ) -> Result<(), StateError> {
        let deposit = self.0;
        match state.validator_index(&deposit.pubkey) {
            Some(index) => state.increase_balance(index, deposit.amount),
            None => {
                let skip = state.verification() == Verification::Skip;
                if skip || self.has_valid_signature(config) {
                    self.add_validator(state)?;
                }
                Ok(())
            }
        }
    }

    /// Whether the deposit's signature proves possession of its key.
    ///
    /// The domain ignores forks, so a deposit stays valid across every fork.
    /// See `is_valid_deposit_signature` in the Electra beacon chain spec.
    #[must_use]
    pub fn has_valid_signature(self, config: &ChainConfig) -> bool {
        let deposit = self.0;
        let message = DepositMessage {
            pubkey: deposit.pubkey,
            withdrawal_credentials: deposit.withdrawal_credentials,
            amount: deposit.amount,
        };
        // Fork-agnostic: the genesis fork version and the zero chain root.
        let domain = Domain::compute(DOMAIN_DEPOSIT, config.genesis_fork_version, Root::ZERO);
        let signing_root = SigningData::signing_root(&message, domain);
        let (Ok(key), Ok(signature)) = (
            PublicKey::from_bytes(&deposit.pubkey.0),
            Signature::from_bytes(&deposit.signature.0),
        ) else {
            return false;
        };
        signature.verify(&key, &signing_root.0)
    }

    /// Appends a new validator and its per-validator entries.
    ///
    /// See `add_validator_to_registry` in the Electra beacon chain spec.
    fn add_validator<S: ParticipationState>(
        self,
        state: &mut CachedState<'_, S>,
    ) -> Result<(), StateError> {
        let deposit = self.0;
        let validator = Validator::from_deposit::<S::Preset>(
            deposit.pubkey,
            deposit.withdrawal_credentials,
            deposit.amount,
        );
        let beacon = &mut *state.beacon;
        beacon
            .push_validator(validator, deposit.amount)
            .map_err(|source| StateError::Capacity {
                list: "validators",
                source,
            })?;
        beacon
            .push_participant()
            .map_err(|source| StateError::Capacity {
                list: "participation",
                source,
            })?;
        state.caches.pubkeys.sync(state.beacon.validators());
        Ok(())
    }
}
