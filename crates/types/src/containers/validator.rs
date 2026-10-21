//! Validator records in the registry.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{BlsPubkey, Bytes32, Epoch, Gwei};

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
