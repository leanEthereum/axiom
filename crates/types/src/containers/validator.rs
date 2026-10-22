//! Validator records in the registry.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{
    BlsPubkey, Bytes32, Epoch, ExecutionAddress, Gwei, Preset,
    constants::{COMPOUNDING_WITHDRAWAL_PREFIX, ETH1_ADDRESS_WITHDRAWAL_PREFIX},
};

/// A validator's identity, stake, and lifecycle epochs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Validator {
    /// Key the validator signs with.
    pub pubkey: BlsPubkey,

    /// Where withdrawals go, tagged by a prefix byte.
    pub withdrawal_credentials: Bytes32,

    /// Balance used for rewards and voting weight, rounded down to whole increments.
    pub effective_balance: Gwei,

    /// Whether the validator has been slashed.
    pub slashed: bool,

    /// Epoch the validator entered the activation queue.
    pub activation_eligibility_epoch: Epoch,

    /// Epoch the validator became active.
    pub activation_epoch: Epoch,

    /// Epoch the validator stops being active.
    pub exit_epoch: Epoch,

    /// Epoch the validator's balance can be withdrawn.
    pub withdrawable_epoch: Epoch,
}

impl Container for Validator {
    const FIELDS: &'static [Option<usize>] = &[
        BlsPubkey::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        bool::FIXED_SIZE,
        Epoch::FIXED_SIZE,
        Epoch::FIXED_SIZE,
        Epoch::FIXED_SIZE,
        Epoch::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.pubkey);
        visitor.field(&self.withdrawal_credentials);
        visitor.field(&self.effective_balance);
        visitor.field(&self.slashed);
        visitor.field(&self.activation_eligibility_epoch);
        visitor.field(&self.activation_epoch);
        visitor.field(&self.exit_epoch);
        visitor.field(&self.withdrawable_epoch);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            pubkey: fields.field()?,
            withdrawal_credentials: fields.field()?,
            effective_balance: fields.field()?,
            slashed: fields.field()?,
            activation_eligibility_epoch: fields.field()?,
            activation_epoch: fields.field()?,
            exit_epoch: fields.field()?,
            withdrawable_epoch: fields.field()?,
        })
    }
}

impl Validator {
    /// Whether the validator is active at an epoch: activated, and not yet exited.
    #[must_use]
    pub fn is_active_at(&self, epoch: Epoch) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    /// Whether the validator may join the activation queue.
    ///
    /// See `is_eligible_for_activation_queue` in the Electra beacon chain spec.
    #[must_use]
    pub fn is_eligible_for_activation_queue<P: Preset>(&self) -> bool {
        self.activation_eligibility_epoch == Epoch::FAR_FUTURE
            && self.effective_balance >= P::MIN_ACTIVATION_BALANCE
    }

    /// Whether the validator may activate, given the latest finalized epoch.
    ///
    /// Its queue placement must be finalized, so a reorg cannot reorder activations.
    #[must_use]
    pub fn is_eligible_for_activation(&self, finalized_epoch: Epoch) -> bool {
        self.activation_eligibility_epoch <= finalized_epoch
            && self.activation_epoch == Epoch::FAR_FUTURE
    }

    /// Whether the validator can still be slashed at an epoch.
    #[must_use]
    pub fn is_slashable_at(&self, epoch: Epoch) -> bool {
        !self.slashed && self.activation_epoch <= epoch && epoch < self.withdrawable_epoch
    }

    /// Whether the withdrawal credentials are an execution address, prefix 0x01.
    #[must_use]
    pub const fn has_eth1_withdrawal_credential(&self) -> bool {
        self.withdrawal_credentials.0[0] == ETH1_ADDRESS_WITHDRAWAL_PREFIX
    }

    /// Whether the withdrawal credentials are compounding, prefix 0x02.
    #[must_use]
    pub const fn has_compounding_withdrawal_credential(&self) -> bool {
        self.withdrawal_credentials.0[0] == COMPOUNDING_WITHDRAWAL_PREFIX
    }

    /// Whether the withdrawal credentials pay out to an execution address, prefix 0x01 or 0x02.
    #[must_use]
    pub const fn has_execution_withdrawal_credential(&self) -> bool {
        self.has_eth1_withdrawal_credential() || self.has_compounding_withdrawal_credential()
    }

    /// The execution address withdrawals go to: the last 20 bytes of the credentials.
    #[must_use]
    pub fn withdrawal_address(&self) -> ExecutionAddress {
        let mut address = [0; 20];
        address.copy_from_slice(&self.withdrawal_credentials.0[12..]);
        ExecutionAddress(address)
    }

    /// Effective balance cap: higher for compounding validators.
    ///
    /// See `get_max_effective_balance` in the Electra beacon chain spec.
    #[must_use]
    pub const fn max_effective_balance<P: Preset>(&self) -> Gwei {
        if self.has_compounding_withdrawal_credential() {
            P::MAX_EFFECTIVE_BALANCE_ELECTRA
        } else {
            P::MIN_ACTIVATION_BALANCE
        }
    }

    /// Whether the whole balance can be withdrawn at an epoch.
    #[must_use]
    pub fn is_fully_withdrawable(&self, balance: Gwei, epoch: Epoch) -> bool {
        self.has_execution_withdrawal_credential()
            && self.withdrawable_epoch <= epoch
            && balance > Gwei::ZERO
    }

    /// Whether the balance above the cap can be skimmed off.
    #[must_use]
    pub fn is_partially_withdrawable<P: Preset>(&self, balance: Gwei) -> bool {
        let max_effective_balance = self.max_effective_balance::<P>();
        self.has_execution_withdrawal_credential()
            && self.effective_balance == max_effective_balance
            && balance > max_effective_balance
    }

    /// Whether a queued partial withdrawal may be paid out.
    ///
    /// See `is_eligible_for_partial_withdrawals` in the Electra beacon chain spec.
    #[must_use]
    pub fn is_eligible_for_partial_withdrawals<P: Preset>(&self, balance: Gwei) -> bool {
        self.exit_epoch == Epoch::FAR_FUTURE
            && self.effective_balance >= P::MIN_ACTIVATION_BALANCE
            && balance > P::MIN_ACTIVATION_BALANCE
    }

    /// A fresh validator for a first deposit, not yet in any queue.
    ///
    /// See `get_validator_from_deposit` in the Electra beacon chain spec.
    #[must_use]
    pub fn from_deposit<P: Preset>(
        pubkey: BlsPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
    ) -> Self {
        let mut validator = Self {
            pubkey,
            withdrawal_credentials,
            effective_balance: Gwei::ZERO,
            slashed: false,
            activation_eligibility_epoch: Epoch::FAR_FUTURE,
            activation_epoch: Epoch::FAR_FUTURE,
            exit_epoch: Epoch::FAR_FUTURE,
            withdrawable_epoch: Epoch::FAR_FUTURE,
        };
        // Round down to whole increments, then cap by the credential type.
        let rounded = amount - Gwei(amount.0 % P::EFFECTIVE_BALANCE_INCREMENT.0);
        validator.effective_balance = rounded.min(validator.max_effective_balance::<P>());
        validator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mainnet;

    fn validator(prefix: u8) -> Validator {
        let mut credentials = [0; 32];
        credentials[0] = prefix;
        credentials[12..].copy_from_slice(&[0xaa; 20]);
        Validator {
            withdrawal_credentials: Bytes32(credentials),
            activation_epoch: Epoch(2),
            exit_epoch: Epoch(10),
            withdrawable_epoch: Epoch(20),
            ..Validator::default()
        }
    }

    #[test]
    fn activity_window_is_half_open() {
        // Active from epoch 2 included to epoch 10 excluded.
        let validator = validator(0x01);

        assert!(!validator.is_active_at(Epoch(1)));
        assert!(validator.is_active_at(Epoch(2)));
        assert!(validator.is_active_at(Epoch(9)));
        assert!(!validator.is_active_at(Epoch(10)));
    }

    #[test]
    fn credential_prefix_sets_the_balance_cap() {
        // 0x01 caps at 32 ether, 0x02 at 2048 ether.
        assert_eq!(
            validator(0x01).max_effective_balance::<Mainnet>(),
            Gwei(32_000_000_000)
        );
        assert_eq!(
            validator(0x02).max_effective_balance::<Mainnet>(),
            Gwei(2_048_000_000_000)
        );
        assert!(!validator(0x00).has_execution_withdrawal_credential());
    }

    #[test]
    fn withdrawal_address_is_the_credential_tail() {
        assert_eq!(
            validator(0x01).withdrawal_address(),
            ExecutionAddress([0xaa; 20])
        );
    }

    #[test]
    fn deposit_rounds_down_and_caps() {
        // 33.7 ether rounds down to 33, then caps at 32 for an 0x01 credential.
        let fresh = Validator::from_deposit::<Mainnet>(
            BlsPubkey::ZERO,
            validator(0x01).withdrawal_credentials,
            Gwei(33_700_000_000),
        );

        assert_eq!(fresh.effective_balance, Gwei(32_000_000_000));
        assert_eq!(fresh.activation_epoch, Epoch::FAR_FUTURE);
    }
}
