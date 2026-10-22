//! Deposits requested by the execution layer, and deposits waiting for churn.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};

use crate::{BlsPubkey, BlsSignature, Bytes32, Gwei, Slot};

/// A deposit relayed by the execution layer.
///
/// See EIP-6110.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DepositRequest {
    /// Key of the new or topped-up validator.
    pub pubkey: BlsPubkey,

    /// Where withdrawals go.
    pub withdrawal_credentials: Bytes32,

    /// Deposited amount.
    pub amount: Gwei,

    /// Proof of possession of the key.
    pub signature: BlsSignature,

    /// Position of the deposit in the deposit contract.
    pub index: u64,
}

impl Container for DepositRequest {
    const FIELDS: &'static [Option<usize>] = &[
        BlsPubkey::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
        u64::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.pubkey);
        visitor.field(&self.withdrawal_credentials);
        visitor.field(&self.amount);
        visitor.field(&self.signature);
        visitor.field(&self.index);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            pubkey: fields.field()?,
            withdrawal_credentials: fields.field()?,
            amount: fields.field()?,
            signature: fields.field()?,
            index: fields.field()?,
        })
    }
}

/// A deposit waiting in the queue for churn.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PendingDeposit {
    /// Key of the new or topped-up validator.
    pub pubkey: BlsPubkey,

    /// Where withdrawals go.
    pub withdrawal_credentials: Bytes32,

    /// Deposited amount.
    pub amount: Gwei,

    /// Proof of possession of the key.
    pub signature: BlsSignature,

    /// Slot the deposit was queued in, which must finalize before it applies.
    pub slot: Slot,
}

impl Container for PendingDeposit {
    const FIELDS: &'static [Option<usize>] = &[
        BlsPubkey::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
        Slot::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.pubkey);
        visitor.field(&self.withdrawal_credentials);
        visitor.field(&self.amount);
        visitor.field(&self.signature);
        visitor.field(&self.slot);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            pubkey: fields.field()?,
            withdrawal_credentials: fields.field()?,
            amount: fields.field()?,
            signature: fields.field()?,
            slot: fields.field()?,
        })
    }
}
