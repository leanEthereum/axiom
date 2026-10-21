//! Deposits, from the deposit contract and from execution requests.

use axiom_ssz::{Const, Container, DecodeError, FieldDecoder, FieldVisitor, Ssz, Vector};

use crate::{BlsPubkey, BlsSignature, Bytes32, Gwei, Slot};

/// Merkle branch of a deposit in the deposit contract tree, plus the mixed-in count.
pub type DepositProof = Vector<Bytes32, Const<33>>;

/// The part of a deposit its signature covers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DepositMessage {
    /// Key of the new or topped-up validator.
    pub pubkey: BlsPubkey,

    /// Where withdrawals go.
    pub withdrawal_credentials: Bytes32,

    /// Deposited amount.
    pub amount: Gwei,
}

impl Container for DepositMessage {
    const FIELDS: &'static [Option<usize>] =
        &[BlsPubkey::FIXED_SIZE, Bytes32::FIXED_SIZE, Gwei::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.pubkey);
        visitor.field(&self.withdrawal_credentials);
        visitor.field(&self.amount);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            pubkey: fields.field()?,
            withdrawal_credentials: fields.field()?,
            amount: fields.field()?,
        })
    }
}

/// A deposit as logged by the deposit contract.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DepositData {
    /// Key of the new or topped-up validator.
    pub pubkey: BlsPubkey,

    /// Where withdrawals go.
    pub withdrawal_credentials: Bytes32,

    /// Deposited amount.
    pub amount: Gwei,

    /// Proof of possession of the key, over the deposit message.
    pub signature: BlsSignature,
}

impl Container for DepositData {
    const FIELDS: &'static [Option<usize>] = &[
        BlsPubkey::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        BlsSignature::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.pubkey);
        visitor.field(&self.withdrawal_credentials);
        visitor.field(&self.amount);
        visitor.field(&self.signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            pubkey: fields.field()?,
            withdrawal_credentials: fields.field()?,
            amount: fields.field()?,
            signature: fields.field()?,
        })
    }
}

/// A deposit with its proof against the deposit contract root.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Deposit {
    /// Branch from the deposit leaf to the contract root.
    pub proof: DepositProof,

    /// The deposit.
    pub data: DepositData,
}

impl Container for Deposit {
    const FIELDS: &'static [Option<usize>] = &[DepositProof::FIXED_SIZE, DepositData::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.proof);
        visitor.field(&self.data);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            proof: fields.field()?,
            data: fields.field()?,
        })
    }
}

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
