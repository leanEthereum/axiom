//! Builder deposit requests: stake for the builder registry, relayed by the execution layer.

use axiom_bls::{PublicKey, Signature};
use axiom_types::{
    ChainConfig, Domain, Epoch, Gwei, Root,
    accessors::BuilderState,
    constants::{BUILDER_WITHDRAWAL_PREFIX, DOMAIN_BUILDER_DEPOSIT},
    gloas::BuilderDepositRequest,
    phase0::{DepositMessage, SigningData},
};

use crate::{
    BlockError, BlockProcessor, Fork, Operation, StateError, gloas::builders::BuilderRegistration,
};

impl<S: Fork + BuilderState> Operation<S> for BuilderDepositRequest {
    /// Registers a new builder, or tops up a known one.
    ///
    /// # Algorithm
    ///
    /// 1. A request without builder credentials is ignored.
    /// 2. A new key joins the registry if it proves possession of the key.
    /// 3. A known key adds to its builder's balance.
    ///    An exited builder that was already paid out starts a new withdrawal delay.
    ///
    /// A known builder needs no proof, since its key proved possession when it joined.
    /// See EIP-8282 and `process_builder_deposit_request` in the Gloas beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        if self.withdrawal_credentials.0[0] != BUILDER_WITHDRAWAL_PREFIX {
            return Ok(());
        }
        let config = processor.config;
        let checks_signatures = processor.checks_signatures();
        let state = &mut *processor.state.beacon;
        let known = state
            .builders()
            .iter()
            .position(|builder| builder.pubkey == self.pubkey);
        let Some(index) = known else {
            if !checks_signatures || BuilderDepositProof(self).holds(config) {
                BuilderRegistration {
                    pubkey: self.pubkey,
                    withdrawal_credentials: self.withdrawal_credentials,
                    amount: self.amount,
                    slot: state.slot(),
                }
                .register(state);
            }
            return Ok(());
        };

        let epoch = state.current_epoch();
        let builder = &mut state.builders_mut()[index];
        // Exited and swept: the deposit gets a fresh delay before the sweep pays it out.
        if builder.withdrawable_epoch != Epoch::FAR_FUTURE && builder.balance == Gwei::ZERO {
            builder.withdrawable_epoch = epoch
                .checked_add(config.min_builder_withdrawability_delay)
                .ok_or(StateError::Overflow {
                    quantity: "builder withdrawable epoch",
                })?;
        }
        builder.balance = builder
            .balance
            .checked_add(self.amount)
            .ok_or(StateError::Overflow {
                quantity: "builder balance",
            })?;
        Ok(())
    }
}

/// A builder deposit's proof of possession of its key.
#[derive(Clone, Copy, Debug)]
struct BuilderDepositProof<'a>(&'a BuilderDepositRequest);

impl BuilderDepositProof<'_> {
    /// Whether the deposit's signature over its message verifies under its key.
    ///
    /// The builder domain keeps validator and builder deposits from replaying as each other.
    /// Like the validator domain, it ignores forks, so a deposit stays valid across them.
    /// See `is_valid_builder_deposit_signature` in the Gloas beacon chain spec.
    fn holds(self, config: &ChainConfig) -> bool {
        let request = self.0;
        let message = DepositMessage {
            pubkey: request.pubkey,
            withdrawal_credentials: request.withdrawal_credentials,
            amount: request.amount,
        };
        let domain = Domain::compute(
            DOMAIN_BUILDER_DEPOSIT,
            config.genesis_fork_version,
            Root::ZERO,
        );
        let root = SigningData::signing_root(&message, domain);
        let (Ok(key), Ok(signature)) = (
            PublicKey::from_bytes(&request.pubkey.0),
            Signature::from_bytes(&request.signature.0),
        ) else {
            return false;
        };
        signature.verify(&key, &root.0)
    }
}
