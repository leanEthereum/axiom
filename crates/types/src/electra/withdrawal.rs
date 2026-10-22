//! Withdrawals requested by the execution layer, and partial withdrawals waiting for their epoch.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{BlsPubkey, Epoch, ExecutionAddress, Gwei, ValidatorIndex};

/// A withdrawal or exit triggered from the execution layer.
///
/// See EIP-7002.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WithdrawalRequest {
    /// Address that sent the request, which must own the credentials.
    pub source_address: ExecutionAddress,

    /// Validator to withdraw from.
    pub validator_pubkey: BlsPubkey,

    /// Amount to withdraw, or zero for a full exit.
    pub amount: Gwei,
}

impl Container for WithdrawalRequest {
    const FIELDS: &'static [Option<usize>] = &[
        ExecutionAddress::FIXED_SIZE,
        BlsPubkey::FIXED_SIZE,
        Gwei::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.source_address);
        visitor.field(&self.validator_pubkey);
        visitor.field(&self.amount);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            source_address: fields.field()?,
            validator_pubkey: fields.field()?,
            amount: fields.field()?,
        })
    }
}

/// A partial withdrawal waiting for its epoch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PendingPartialWithdrawal {
    /// Validator to withdraw from.
    pub validator_index: ValidatorIndex,

    /// Amount to withdraw.
    pub amount: Gwei,

    /// Earliest epoch the withdrawal may happen.
    pub withdrawable_epoch: Epoch,
}

impl Container for PendingPartialWithdrawal {
    const FIELDS: &'static [Option<usize>] = &[
        ValidatorIndex::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        Epoch::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.validator_index);
        visitor.field(&self.amount);
        visitor.field(&self.withdrawable_epoch);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            validator_index: fields.field()?,
            amount: fields.field()?,
            withdrawable_epoch: fields.field()?,
        })
    }
}
