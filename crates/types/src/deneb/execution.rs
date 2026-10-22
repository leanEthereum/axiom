//! Execution payloads of Deneb, which account for blob gas.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz, U256};

use crate::{
    Bytes32, ExecutionAddress, Hash32, Preset, Root, VersionedHash,
    deneb::{ExtraData, LogsBloom, Transactions, Withdrawals},
};

/// Versioned hashes of a block's blob commitments.
pub type VersionedHashes<P> = List<VersionedHash, <P as Preset>::MaxBlobCommitmentsPerBlock>;

/// An execution block, as carried in a beacon block.
///
/// See the Deneb beacon chain spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionPayload<P: Preset> {
    /// Hash of the parent execution block.
    pub parent_hash: Hash32,

    /// Address that receives priority fees.
    pub fee_recipient: ExecutionAddress,

    /// Root of the execution state after the block.
    pub state_root: Bytes32,

    /// Root of the transaction receipts.
    pub receipts_root: Bytes32,

    /// Bloom filter over the logs.
    pub logs_bloom: LogsBloom<P>,

    /// Randao mix the execution layer exposes as its randomness.
    pub prev_randao: Bytes32,

    /// Execution block number.
    pub block_number: u64,

    /// Gas limit of the block.
    pub gas_limit: u64,

    /// Gas used by the block.
    pub gas_used: u64,

    /// Block timestamp, which must match the slot.
    pub timestamp: u64,

    /// Free-form bytes chosen by the block builder.
    pub extra_data: ExtraData<P>,

    /// EIP-1559 base fee.
    pub base_fee_per_gas: U256,

    /// Hash of the execution block.
    pub block_hash: Hash32,

    /// The transactions.
    pub transactions: Transactions<P>,

    /// Withdrawals the consensus layer requested.
    pub withdrawals: Withdrawals<P>,

    /// Blob gas used by the block.
    pub blob_gas_used: u64,

    /// Excess blob gas carried into the block, which sets the blob fee.
    pub excess_blob_gas: u64,
}

impl<P: Preset> Container for ExecutionPayload<P> {
    const FIELDS: &'static [Option<usize>] = &[
        Hash32::FIXED_SIZE,
        ExecutionAddress::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        <LogsBloom<P>>::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        u64::FIXED_SIZE,
        u64::FIXED_SIZE,
        u64::FIXED_SIZE,
        u64::FIXED_SIZE,
        <ExtraData<P>>::FIXED_SIZE,
        U256::FIXED_SIZE,
        Hash32::FIXED_SIZE,
        <Transactions<P>>::FIXED_SIZE,
        <Withdrawals<P>>::FIXED_SIZE,
        u64::FIXED_SIZE,
        u64::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.parent_hash);
        visitor.field(&self.fee_recipient);
        visitor.field(&self.state_root);
        visitor.field(&self.receipts_root);
        visitor.field(&self.logs_bloom);
        visitor.field(&self.prev_randao);
        visitor.field(&self.block_number);
        visitor.field(&self.gas_limit);
        visitor.field(&self.gas_used);
        visitor.field(&self.timestamp);
        visitor.field(&self.extra_data);
        visitor.field(&self.base_fee_per_gas);
        visitor.field(&self.block_hash);
        visitor.field(&self.transactions);
        visitor.field(&self.withdrawals);
        visitor.field(&self.blob_gas_used);
        visitor.field(&self.excess_blob_gas);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            parent_hash: fields.field()?,
            fee_recipient: fields.field()?,
            state_root: fields.field()?,
            receipts_root: fields.field()?,
            logs_bloom: fields.field()?,
            prev_randao: fields.field()?,
            block_number: fields.field()?,
            gas_limit: fields.field()?,
            gas_used: fields.field()?,
            timestamp: fields.field()?,
            extra_data: fields.field()?,
            base_fee_per_gas: fields.field()?,
            block_hash: fields.field()?,
            transactions: fields.field()?,
            withdrawals: fields.field()?,
            blob_gas_used: fields.field()?,
            excess_blob_gas: fields.field()?,
        })
    }
}

/// An execution payload with its lists replaced by their roots.
///
/// See the Deneb beacon chain spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionPayloadHeader<P: Preset> {
    /// Hash of the parent execution block.
    pub parent_hash: Hash32,

    /// Address that receives priority fees.
    pub fee_recipient: ExecutionAddress,

    /// Root of the execution state after the block.
    pub state_root: Bytes32,

    /// Root of the transaction receipts.
    pub receipts_root: Bytes32,

    /// Bloom filter over the logs.
    pub logs_bloom: LogsBloom<P>,

    /// Randao mix the execution layer exposes as its randomness.
    pub prev_randao: Bytes32,

    /// Execution block number.
    pub block_number: u64,

    /// Gas limit of the block.
    pub gas_limit: u64,

    /// Gas used by the block.
    pub gas_used: u64,

    /// Block timestamp, which must match the slot.
    pub timestamp: u64,

    /// Free-form bytes chosen by the block builder.
    pub extra_data: ExtraData<P>,

    /// EIP-1559 base fee.
    pub base_fee_per_gas: U256,

    /// Hash of the execution block.
    pub block_hash: Hash32,

    /// Root of the transactions.
    pub transactions_root: Root,

    /// Root of the withdrawals.
    pub withdrawals_root: Root,

    /// Blob gas used by the block.
    pub blob_gas_used: u64,

    /// Excess blob gas carried into the block, which sets the blob fee.
    pub excess_blob_gas: u64,
}

impl<P: Preset> Container for ExecutionPayloadHeader<P> {
    const FIELDS: &'static [Option<usize>] = &[
        Hash32::FIXED_SIZE,
        ExecutionAddress::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        <LogsBloom<P>>::FIXED_SIZE,
        Bytes32::FIXED_SIZE,
        u64::FIXED_SIZE,
        u64::FIXED_SIZE,
        u64::FIXED_SIZE,
        u64::FIXED_SIZE,
        <ExtraData<P>>::FIXED_SIZE,
        U256::FIXED_SIZE,
        Hash32::FIXED_SIZE,
        Root::FIXED_SIZE,
        Root::FIXED_SIZE,
        u64::FIXED_SIZE,
        u64::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.parent_hash);
        visitor.field(&self.fee_recipient);
        visitor.field(&self.state_root);
        visitor.field(&self.receipts_root);
        visitor.field(&self.logs_bloom);
        visitor.field(&self.prev_randao);
        visitor.field(&self.block_number);
        visitor.field(&self.gas_limit);
        visitor.field(&self.gas_used);
        visitor.field(&self.timestamp);
        visitor.field(&self.extra_data);
        visitor.field(&self.base_fee_per_gas);
        visitor.field(&self.block_hash);
        visitor.field(&self.transactions_root);
        visitor.field(&self.withdrawals_root);
        visitor.field(&self.blob_gas_used);
        visitor.field(&self.excess_blob_gas);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            parent_hash: fields.field()?,
            fee_recipient: fields.field()?,
            state_root: fields.field()?,
            receipts_root: fields.field()?,
            logs_bloom: fields.field()?,
            prev_randao: fields.field()?,
            block_number: fields.field()?,
            gas_limit: fields.field()?,
            gas_used: fields.field()?,
            timestamp: fields.field()?,
            extra_data: fields.field()?,
            base_fee_per_gas: fields.field()?,
            block_hash: fields.field()?,
            transactions_root: fields.field()?,
            withdrawals_root: fields.field()?,
            blob_gas_used: fields.field()?,
            excess_blob_gas: fields.field()?,
        })
    }
}

/// Everything the execution engine needs to validate a payload.
///
/// See the Deneb beacon chain spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewPayloadRequest<P: Preset> {
    /// The payload.
    pub execution_payload: ExecutionPayload<P>,

    /// Hashes of the block's blob commitments.
    pub versioned_hashes: VersionedHashes<P>,

    /// Root of the parent beacon block, see EIP-4788.
    pub parent_beacon_block_root: Root,
}

impl<P: Preset> Container for NewPayloadRequest<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <ExecutionPayload<P>>::FIXED_SIZE,
        <VersionedHashes<P>>::FIXED_SIZE,
        Root::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.execution_payload);
        visitor.field(&self.versioned_hashes);
        visitor.field(&self.parent_beacon_block_root);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            execution_payload: fields.field()?,
            versioned_hashes: fields.field()?,
            parent_beacon_block_root: fields.field()?,
        })
    }
}
