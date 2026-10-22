//! The withdrawals step of Capella: sweeping validators for balances to pay out.

use axiom_types::{
    Epoch, Gwei, Preset, ValidatorIndex, WithdrawalIndex, accessors::WithdrawalState,
    capella::Withdrawal, phase0::Validator,
};

use crate::{BlockError, BlockProcessor, Fork, Operation, StateError};

/// The withdrawals a payload must contain, found by sweeping the registry.
///
/// The sweep resumes where the last one stopped, and wraps around the registry.
/// It inspects a bounded window of validators, and stops early once the payload is full.
///
/// See `get_expected_withdrawals` in the Capella beacon chain spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidatorSweep {
    /// The withdrawals, in payload order.
    pub withdrawals: Vec<Withdrawal>,
}

impl ValidatorSweep {
    /// The withdrawals due at a state.
    ///
    /// A sweep window never exceeds the registry, so it meets each validator at most once.
    /// Each balance it reads is therefore untouched by earlier withdrawals of the same sweep.
    ///
    /// See `get_validators_sweep_withdrawals` in the Capella beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the sweep cursor or a balance points past the registry.
    pub fn compute<S: WithdrawalState + ?Sized>(state: &S) -> Result<Self, StateError> {
        let epoch = state.current_epoch();
        let validators = state.validators();
        let balances = state.balances();
        let count = validators.len() as u64;
        let window = count.min(S::Preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
        let mut withdrawals = Vec::new();
        let mut next_index = state.next_withdrawal_index();
        let mut validator_index = state.next_withdrawal_validator_index();
        for _ in 0..window {
            if withdrawals.len() as u64 >= S::Preset::MAX_WITHDRAWALS_PER_PAYLOAD {
                break;
            }
            let position = validator_index.as_usize();
            let (Some(validator), Some(&balance)) =
                (validators.get(position), balances.get(position))
            else {
                return Err(StateError::UnknownValidator {
                    index: validator_index,
                    registry_size: validators.len(),
                });
            };
            if let Some(amount) = Self::withdrawable::<S::Preset>(validator, balance, epoch) {
                withdrawals.push(Withdrawal {
                    index: next_index,
                    validator_index,
                    address: validator.withdrawal_address(),
                    amount,
                });
                next_index.0 += 1;
            }
            validator_index = ValidatorIndex((validator_index.0 + 1) % count);
        }
        Ok(Self { withdrawals })
    }

    /// What a validator withdraws in a sweep: everything, the excess, or nothing.
    ///
    /// Only 0x01 credentials name an execution address before Electra.
    /// A withdrawable validator takes its whole balance.
    /// A validator at the maximum effective balance skims what lies above it.
    ///
    /// See `is_fully_withdrawable_validator` in the Capella beacon chain spec.
    /// See `is_partially_withdrawable_validator` there too.
    fn withdrawable<P: Preset>(validator: &Validator, balance: Gwei, epoch: Epoch) -> Option<Gwei> {
        if !validator.has_eth1_withdrawal_credential() {
            return None;
        }
        if validator.withdrawable_epoch <= epoch && balance > Gwei::ZERO {
            return Some(balance);
        }
        let cap = P::MAX_EFFECTIVE_BALANCE;
        (validator.effective_balance == cap && balance > cap).then(|| balance - cap)
    }
}

/// A payload's withdrawals, checked and paid by Capella's rules.
///
/// Deneb kept this rule.
/// Electra added the queue of partial withdrawals before the sweep, in its own type.
#[derive(Clone, Copy, Debug)]
pub struct PayloadWithdrawals<'a>(pub &'a [Withdrawal]);

impl<S: Fork + WithdrawalState> Operation<S> for PayloadWithdrawals<'_> {
    /// Checks a payload's withdrawals against the sweep, then pays them.
    ///
    /// The payload must carry exactly the expected withdrawals, in order.
    ///
    /// See `process_withdrawals` in the Capella beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let actual = self.0;
        let expected = ValidatorSweep::compute(processor.state.beacon())?.withdrawals;
        if actual != expected.as_slice() {
            return Err(BlockError::WithdrawalsMismatch {
                expected: expected.len(),
                actual: actual.len(),
                first_difference: actual
                    .iter()
                    .zip(&expected)
                    .take_while(|(actual, expected)| actual == expected)
                    .count(),
            });
        }

        for withdrawal in &expected {
            processor
                .state
                .decrease_balance(withdrawal.validator_index, withdrawal.amount)?;
        }

        let state = &mut *processor.state.beacon;
        if let Some(latest) = expected.last() {
            *state.next_withdrawal_index_mut() = WithdrawalIndex(latest.index.0 + 1);
        }

        // A full payload resumes the sweep right after its last withdrawal.
        // Otherwise the sweep advances by its whole window.
        let count = state.validators().len() as u64;
        let next = match expected.last() {
            Some(latest) if expected.len() as u64 == S::Preset::MAX_WITHDRAWALS_PER_PAYLOAD => {
                latest.validator_index.0 + 1
            }
            _ => {
                state.next_withdrawal_validator_index().0
                    + S::Preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP
            }
        };
        *state.next_withdrawal_validator_index_mut() = ValidatorIndex(next % count);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Bytes32, Minimal};

    use super::*;

    const ETH: u64 = 1_000_000_000;

    fn validator(prefix: u8, effective_eth: u64, withdrawable_epoch: Epoch) -> Validator {
        let mut credentials = [0; 32];
        credentials[0] = prefix;
        Validator {
            withdrawal_credentials: Bytes32(credentials),
            effective_balance: Gwei(effective_eth * ETH),
            withdrawable_epoch,
            ..Validator::default()
        }
    }

    #[test]
    fn the_sweep_pays_full_and_partial_withdrawals_to_eth1_credentials_only() {
        let epoch = Epoch(10);

        // A withdrawable 0x01 validator with 20 ETH takes all 20 ETH.
        let exited = validator(0x01, 20, Epoch(5));
        assert_eq!(
            ValidatorSweep::withdrawable::<Minimal>(&exited, Gwei(20 * ETH), epoch),
            Some(Gwei(20 * ETH))
        );

        // An active 0x01 validator at 32 ETH effective with 33 ETH skims 1 ETH.
        let active = validator(0x01, 32, Epoch::FAR_FUTURE);
        assert_eq!(
            ValidatorSweep::withdrawable::<Minimal>(&active, Gwei(33 * ETH), epoch),
            Some(Gwei(ETH))
        );

        // A 0x02 validator withdraws nothing before Electra, even when withdrawable.
        let compounding = validator(0x02, 32, Epoch(5));
        assert_eq!(
            ValidatorSweep::withdrawable::<Minimal>(&compounding, Gwei(33 * ETH), epoch),
            None
        );

        // A 0x01 validator below the maximum effective balance keeps its excess.
        let below = validator(0x01, 31, Epoch::FAR_FUTURE);
        assert_eq!(
            ValidatorSweep::withdrawable::<Minimal>(&below, Gwei(33 * ETH), epoch),
            None
        );
    }
}
