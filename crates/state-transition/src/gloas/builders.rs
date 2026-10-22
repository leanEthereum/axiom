//! The builder registry, grown from builder deposits.

use std::collections::HashSet;

use axiom_types::{
    BlsPubkey, Bytes32, ChainConfig, Epoch, ExecutionAddress, Gwei, Preset, Slot,
    accessors::{BuilderState, CoreState},
    constants::{BUILDER_WITHDRAWAL_PREFIX, PAYLOAD_BUILDER_VERSION},
    electra::PendingDeposit,
    gloas::{BeaconState, Builder},
};

use crate::{CachedState, StateError, Verification, electra::deposits::DepositApplication};

/// The pending deposits at the Gloas fork, sorted into builders and validators.
///
/// Builder deposits made before the fork waited in the validator queue.
/// At the fork they leave it and join the builder registry.
#[derive(Clone, Copy, Debug)]
pub struct BuilderDeposits<'a> {
    /// The chain configuration, whose genesis fork version signs deposits.
    config: &'a ChainConfig,
}

impl<'a> BuilderDeposits<'a> {
    /// Builder deposits checked under a configuration.
    #[must_use]
    pub const fn new(config: &'a ChainConfig) -> Self {
        Self { config }
    }

    /// Moves builder deposits from the pending queue into the builder registry.
    ///
    /// # Algorithm
    ///
    /// Walk the queue in order.
    ///
    /// - A deposit for an existing validator stays in the queue.
    /// - A deposit for an existing builder tops up that builder.
    /// - A deposit without builder credentials stays in the queue.
    /// - A deposit whose key a queued validator deposit already claims stays in the queue.
    /// - A deposit with an invalid signature is dropped.
    /// - Any other deposit registers a new builder.
    ///
    /// See `onboard_builders_from_pending_deposits` in the Gloas fork spec.
    ///
    /// # Errors
    ///
    /// Fails when a builder's balance overflows.
    pub fn onboard<P: Preset>(
        self,
        state: &mut CachedState<'_, BeaconState<P>>,
    ) -> Result<(), StateError> {
        let validator_keys: HashSet<BlsPubkey> = state
            .beacon()
            .validators()
            .iter()
            .map(|validator| validator.pubkey)
            .collect();
        let queue = state.beacon.pending_deposits.clone().into_vec();
        let mut kept: Vec<PendingDeposit> = Vec::new();
        for deposit in queue {
            if validator_keys.contains(&deposit.pubkey) {
                kept.push(deposit);
                continue;
            }
            let builders = state.beacon.builders();
            match builders
                .iter()
                .position(|builder| builder.pubkey == deposit.pubkey)
            {
                Some(index) => {
                    let builder = &mut state.beacon.builders_mut()[index];
                    builder.balance = builder.balance.checked_add(deposit.amount).ok_or(
                        StateError::Overflow {
                            quantity: "builder balance",
                        },
                    )?;
                }
                None => {
                    if deposit.withdrawal_credentials.0[0] != BUILDER_WITHDRAWAL_PREFIX
                        || self.is_pending_validator(state, &kept, &deposit.pubkey)
                    {
                        kept.push(deposit);
                        continue;
                    }
                    if !self.has_valid_signature(state, &deposit) {
                        continue;
                    }
                    BuilderRegistration {
                        pubkey: deposit.pubkey,
                        withdrawal_credentials: deposit.withdrawal_credentials,
                        amount: deposit.amount,
                        slot: deposit.slot,
                    }
                    .register(state.beacon);
                }
            }
        }
        state.beacon.pending_deposits = kept.into();
        Ok(())
    }

    /// Whether a queued deposit with a valid signature already claims a key for a validator.
    ///
    /// See `is_pending_validator` in the Gloas beacon chain spec.
    fn is_pending_validator<P: Preset>(
        self,
        state: &CachedState<'_, BeaconState<P>>,
        queue: &[PendingDeposit],
        pubkey: &BlsPubkey,
    ) -> bool {
        queue
            .iter()
            .filter(|deposit| deposit.pubkey == *pubkey)
            .any(|deposit| self.has_valid_signature(state, deposit))
    }

    /// Whether a deposit proves possession of its key, unless signatures are skipped.
    fn has_valid_signature<P: Preset>(
        self,
        state: &CachedState<'_, BeaconState<P>>,
        deposit: &PendingDeposit,
    ) -> bool {
        state.verification() == Verification::Skip
            || DepositApplication(deposit).has_valid_signature(self.config)
    }
}

/// A builder joining the registry, from a deposit with builder credentials.
///
/// Builders join at the Gloas fork from the validator queue, and afterwards from deposit requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuilderRegistration {
    /// The builder's key.
    pub pubkey: BlsPubkey,
    /// The deposit's credentials, whose last twenty bytes are the execution address.
    pub withdrawal_credentials: Bytes32,
    /// The deposited balance.
    pub amount: Gwei,
    /// Slot the deposit was made in, whose epoch dates the builder.
    pub slot: Slot,
}

impl BuilderRegistration {
    /// Registers the builder, reusing the slot of an exited builder with nothing left.
    ///
    /// See `add_builder_to_registry` and `get_index_for_new_builder` in the Gloas spec.
    pub fn register<S: BuilderState>(self, state: &mut S) {
        let current = state.current_epoch();
        let mut address = [0; 20];
        address.copy_from_slice(&self.withdrawal_credentials.0[12..]);
        let builder = Builder {
            pubkey: self.pubkey,
            version: PAYLOAD_BUILDER_VERSION,
            execution_address: ExecutionAddress(address),
            balance: self.amount,
            deposit_epoch: self.slot.epoch::<S::Preset>(),
            withdrawable_epoch: Epoch::FAR_FUTURE,
        };
        let builders = state.builders_mut();
        let reusable = builders.iter().position(|existing| {
            existing.withdrawable_epoch <= current && existing.balance == Gwei::ZERO
        });
        match reusable {
            Some(index) => builders[index] = builder,
            None => builders.push(builder),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;

    use super::*;

    #[test]
    fn an_exited_empty_builder_slot_is_reused() {
        // Fixture state: epoch 3, builder 0 exited at epoch 2 with nothing left, builder 1 active.
        let mut state = BeaconState::<Minimal> {
            slot: Epoch(3).start_slot::<Minimal>(),
            ..Default::default()
        };
        state.builders.push(Builder {
            withdrawable_epoch: Epoch(2),
            ..Default::default()
        });
        state.builders.push(Builder {
            withdrawable_epoch: Epoch::FAR_FUTURE,
            balance: Gwei(5),
            ..Default::default()
        });

        // A deposit of 7 Gwei from slot 9, epoch 1 of the minimal preset, with builder credentials.
        let mut credentials = [0; 32];
        credentials[0] = BUILDER_WITHDRAWAL_PREFIX;
        credentials[31] = 0xaa;
        BuilderRegistration {
            pubkey: BlsPubkey::default(),
            withdrawal_credentials: Bytes32(credentials),
            amount: Gwei(7),
            slot: Slot(9),
        }
        .register(&mut state);

        // The new builder takes slot 0, and the registry keeps two entries.
        assert_eq!(state.builders.len(), 2);
        let mut address = [0; 20];
        address[19] = 0xaa;
        assert_eq!(
            state.builders[0],
            Builder {
                pubkey: BlsPubkey::default(),
                version: PAYLOAD_BUILDER_VERSION,
                execution_address: ExecutionAddress(address),
                balance: Gwei(7),
                deposit_epoch: Epoch(1),
                withdrawable_epoch: Epoch::FAR_FUTURE,
            }
        );
    }
}
