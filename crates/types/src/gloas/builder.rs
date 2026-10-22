//! Builders, the registry of stakers who sell execution payloads to proposers.
//!
//! See EIP-7732 and the Gloas beacon chain spec.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, ProgressiveList, Ssz, Vector};

use crate::{
    BlsPubkey, BlsSignature, BuilderIndex, Bytes32, Epoch, ExecutionAddress, Gwei, Preset,
    ValidatorIndex,
};

/// The builder registry.
pub type Builders = ProgressiveList<Builder>;

/// Payments owed to builders, one per slot of the previous and current epochs.
pub type BuilderPendingPayments<P> =
    Vector<BuilderPendingPayment, <P as Preset>::BuilderPendingPaymentsSlots>;

/// Builder payments waiting to be withdrawn.
pub type BuilderPendingWithdrawals = ProgressiveList<BuilderPendingWithdrawal>;

/// A builder's identity, balance, and lifecycle epochs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Builder {
    /// Key the builder signs bids and envelopes with.
    pub pubkey: BlsPubkey,

    /// Version of the builder record, which fixes how the rest is read.
    pub version: u8,

    /// Address the builder's balance withdraws to.
    pub execution_address: ExecutionAddress,

    /// Balance that backs the builder's bids.
    pub balance: Gwei,

    /// Epoch the builder's deposit was processed.
    pub deposit_epoch: Epoch,

    /// Epoch the builder may withdraw from, or the far future while active.
    pub withdrawable_epoch: Epoch,
}

impl Builder {
    /// Whether the builder may bid: its deposit is finalized, and it has not started to exit.
    ///
    /// See `is_active_builder` in the Gloas beacon chain spec.
    #[must_use]
    pub fn is_active(&self, finalized_epoch: Epoch) -> bool {
        self.deposit_epoch < finalized_epoch && self.withdrawable_epoch == Epoch::FAR_FUTURE
    }
}

impl Container for Builder {
    const FIELDS: &'static [Option<usize>] = &[
        BlsPubkey::FIXED_SIZE,
        u8::FIXED_SIZE,
        ExecutionAddress::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        Epoch::FIXED_SIZE,
        Epoch::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.pubkey);
        visitor.field(&self.version);
        visitor.field(&self.execution_address);
        visitor.field(&self.balance);
        visitor.field(&self.deposit_epoch);
        visitor.field(&self.withdrawable_epoch);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            pubkey: fields.field()?,
            version: fields.field()?,
            execution_address: fields.field()?,
            balance: fields.field()?,
            deposit_epoch: fields.field()?,
            withdrawable_epoch: fields.field()?,
        })
    }
}

/// A bid's payment, held until enough of the payload committee saw the payload.
///
/// The payment is released once its weight reaches the quorum, and dropped otherwise.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderPendingPayment {
    /// Effective balance of the attesters that saw the payload on time.
    pub weight: Gwei,

    /// The withdrawal that pays the proposer.
    pub withdrawal: BuilderPendingWithdrawal,

    /// The proposer the bid pays.
    pub proposer_index: ValidatorIndex,
}

impl Container for BuilderPendingPayment {
    const FIELDS: &'static [Option<usize>] = &[
        Gwei::FIXED_SIZE,
        BuilderPendingWithdrawal::FIXED_SIZE,
        ValidatorIndex::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.weight);
        visitor.field(&self.withdrawal);
        visitor.field(&self.proposer_index);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            weight: fields.field()?,
            withdrawal: fields.field()?,
            proposer_index: fields.field()?,
        })
    }
}

/// A transfer out of a builder's balance, waiting in the withdrawal queue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderPendingWithdrawal {
    /// Address the ether goes to.
    pub fee_recipient: ExecutionAddress,

    /// Amount withdrawn.
    pub amount: Gwei,

    /// Builder the ether leaves.
    pub builder_index: BuilderIndex,
}

impl Container for BuilderPendingWithdrawal {
    const FIELDS: &'static [Option<usize>] = &[
        ExecutionAddress::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        BuilderIndex::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.fee_recipient);
        visitor.field(&self.amount);
        visitor.field(&self.builder_index);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            fee_recipient: fields.field()?,
            amount: fields.field()?,
            builder_index: fields.field()?,
        })
    }
}

/// A builder deposit triggered from the execution layer.
///
/// See EIP-8282.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderDepositRequest {
    /// Key of the new or topped-up builder.
    pub pubkey: BlsPubkey,

    /// Credentials naming the builder's execution address.
    pub withdrawal_credentials: Bytes32,

    /// Deposited amount.
    pub amount: Gwei,

    /// Proof of possession of the key.
    pub signature: BlsSignature,
}

impl Container for BuilderDepositRequest {
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

/// A builder exit triggered from the execution layer.
///
/// See EIP-8282.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuilderExitRequest {
    /// Address that sent the request, which must own the builder.
    pub source_address: ExecutionAddress,

    /// Builder to exit.
    pub pubkey: BlsPubkey,
}

impl Container for BuilderExitRequest {
    const FIELDS: &'static [Option<usize>] = &[ExecutionAddress::FIXED_SIZE, BlsPubkey::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.source_address);
        visitor.field(&self.pubkey);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            source_address: fields.field()?,
            pubkey: fields.field()?,
        })
    }
}
