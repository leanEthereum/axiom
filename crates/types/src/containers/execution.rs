//! Execution payloads and the requests the execution layer passes to consensus.

use axiom_ssz::{
    ByteList, ByteVector, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz, U256,
};

use crate::{
    Bytes32, ConsolidationRequest, DepositRequest, ExecutionAddress, Hash32, Preset, Root,
    VersionedHash, Withdrawal, WithdrawalRequest,
};

/// Bloom filter over the logs of a payload.
pub type LogsBloom<P> = ByteVector<<P as Preset>::BytesPerLogsBloom>;

/// Free-form bytes chosen by the block builder.
pub type ExtraData<P> = ByteList<<P as Preset>::MaxExtraDataBytes>;

/// An opaque, RLP-encoded execution transaction.
pub type Transaction<P> = ByteList<<P as Preset>::MaxBytesPerTransaction>;

/// Transactions of a payload.
pub type Transactions<P> = List<Transaction<P>, <P as Preset>::MaxTransactionsPerPayload>;

/// Withdrawals of a payload.
pub type Withdrawals<P> = List<Withdrawal, <P as Preset>::MaxWithdrawalsPerPayload>;

/// Versioned hashes of a block's blob commitments.
pub type VersionedHashes<P> = List<VersionedHash, <P as Preset>::MaxBlobCommitmentsPerBlock>;

/// Deposit requests of a payload.
pub type DepositRequests<P> = List<DepositRequest, <P as Preset>::MaxDepositRequestsPerPayload>;

/// Withdrawal requests of a payload.
pub type WithdrawalRequests<P> =
    List<WithdrawalRequest, <P as Preset>::MaxWithdrawalRequestsPerPayload>;

/// Consolidation requests of a payload.
pub type ConsolidationRequests<P> =
    List<ConsolidationRequest, <P as Preset>::MaxConsolidationRequestsPerPayload>;

/// An execution block, as carried in a beacon block.
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

    /// Excess blob gas carried into the block.
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

/// Requests the execution layer passes to the consensus layer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionRequests<P: Preset> {
    /// Deposit requests, see EIP-6110.
    pub deposits: DepositRequests<P>,

    /// Withdrawal requests, see EIP-7002.
    pub withdrawals: WithdrawalRequests<P>,

    /// Consolidation requests, see EIP-7251.
    pub consolidations: ConsolidationRequests<P>,
}

impl<P: Preset> Container for ExecutionRequests<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <DepositRequests<P>>::FIXED_SIZE,
        <WithdrawalRequests<P>>::FIXED_SIZE,
        <ConsolidationRequests<P>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.deposits);
        visitor.field(&self.withdrawals);
        visitor.field(&self.consolidations);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            deposits: fields.field()?,
            withdrawals: fields.field()?,
            consolidations: fields.field()?,
        })
    }
}

/// Everything the execution engine needs to validate a payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewPayloadRequest<P: Preset> {
    /// The payload.
    pub execution_payload: ExecutionPayload<P>,

    /// Hashes of the block's blob commitments.
    pub versioned_hashes: VersionedHashes<P>,

    /// Root of the parent beacon block, see EIP-4788.
    pub parent_beacon_block_root: Root,

    /// Requests the payload produced.
    pub execution_requests: ExecutionRequests<P>,
}

impl<P: Preset> Container for NewPayloadRequest<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <ExecutionPayload<P>>::FIXED_SIZE,
        <VersionedHashes<P>>::FIXED_SIZE,
        Root::FIXED_SIZE,
        <ExecutionRequests<P>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.execution_payload);
        visitor.field(&self.versioned_hashes);
        visitor.field(&self.parent_beacon_block_root);
        visitor.field(&self.execution_requests);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            execution_payload: fields.field()?,
            versioned_hashes: fields.field()?,
            parent_beacon_block_root: fields.field()?,
            execution_requests: fields.field()?,
        })
    }
}
