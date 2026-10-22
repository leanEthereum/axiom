//! Execution payload bids, a builder's offer to deliver a slot's payload.
//!
//! See EIP-7732 and the Gloas beacon chain spec.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, Merkleization, Ssz};

use crate::{
    BlsSignature, BuilderIndex, Bytes32, ExecutionAddress, Gwei, Hash32, Root, Slot,
    gloas::BlobKzgCommitments,
};

/// A builder's commitment to the payload it will reveal for a slot.
///
/// The proposer includes the bid in its block, and the builder pays the value whether or not it reveals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionPayloadBid {
    /// Execution block the payload builds on.
    pub parent_block_hash: Hash32,

    /// Beacon block the bid is for the child of.
    pub parent_block_root: Root,

    /// Hash of the promised execution block.
    pub block_hash: Hash32,

    /// Randao mix the payload must expose.
    pub prev_randao: Bytes32,

    /// Address that receives the payload's priority fees.
    pub fee_recipient: ExecutionAddress,

    /// Gas limit of the promised execution block.
    pub gas_limit: u64,

    /// The builder, or the self-build marker when the proposer builds.
    pub builder_index: BuilderIndex,

    /// Slot of the bid.
    pub slot: Slot,

    /// Amount the builder pays the proposer from its consensus balance.
    pub value: Gwei,

    /// Amount the builder pays the proposer within the execution block.
    pub execution_payment: Gwei,

    /// Commitments to the payload's blobs.
    pub blob_kzg_commitments: BlobKzgCommitments,

    /// Root of the execution requests the payload will carry.
    pub execution_requests_root: Root,
}

impl Container for ExecutionPayloadBid {
    const FIELDS: &'static [Option<usize>] = &[
        Hash32::FIXED_SIZE,
        Root::FIXED_SIZE,
        Hash32::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        ExecutionAddress::FIXED_SIZE,
        u64::FIXED_SIZE,
        BuilderIndex::FIXED_SIZE,
        Slot::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        Gwei::FIXED_SIZE,
        BlobKzgCommitments::FIXED_SIZE,
        Root::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true; 12]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.parent_block_hash);
        visitor.field(&self.parent_block_root);
        visitor.field(&self.block_hash);
        visitor.field(&self.prev_randao);
        visitor.field(&self.fee_recipient);
        visitor.field(&self.gas_limit);
        visitor.field(&self.builder_index);
        visitor.field(&self.slot);
        visitor.field(&self.value);
        visitor.field(&self.execution_payment);
        visitor.field(&self.blob_kzg_commitments);
        visitor.field(&self.execution_requests_root);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            parent_block_hash: fields.field()?,
            parent_block_root: fields.field()?,
            block_hash: fields.field()?,
            prev_randao: fields.field()?,
            fee_recipient: fields.field()?,
            gas_limit: fields.field()?,
            builder_index: fields.field()?,
            slot: fields.field()?,
            value: fields.field()?,
            execution_payment: fields.field()?,
            blob_kzg_commitments: fields.field()?,
            execution_requests_root: fields.field()?,
        })
    }
}

/// A bid with its builder's signature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedExecutionPayloadBid {
    /// The bid.
    pub message: ExecutionPayloadBid,

    /// Builder's signature.
    pub signature: BlsSignature,
}

impl Container for SignedExecutionPayloadBid {
    const FIELDS: &'static [Option<usize>] =
        &[ExecutionPayloadBid::FIXED_SIZE, BlsSignature::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.message);
        visitor.field(&self.signature);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            message: fields.field()?,
            signature: fields.field()?,
        })
    }
}
