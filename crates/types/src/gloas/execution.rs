//! Execution payloads and requests of Gloas, with unbounded lists and new builder requests.
//!
//! See EIP-7688, EIP-7928, EIP-7843, and EIP-8282.

use axiom_ssz::{
    Container, DecodeError, FieldDecoder, FieldVisitor, Merkleization, ProgressiveList, Ssz, U256,
};

use crate::{
    Bytes32, ExecutionAddress, Hash32, KzgCommitment, Preset, Root,
    gloas::{
        BuilderDepositRequest, BuilderExitRequest, ConsolidationRequest, DepositRequest, ExtraData,
        LogsBloom, VersionedHashes, Withdrawal, WithdrawalRequest,
    },
};

/// An opaque, RLP-encoded execution transaction.
pub type Transaction = ProgressiveList<u8>;

/// Transactions of a payload.
pub type Transactions = ProgressiveList<Transaction>;

/// Withdrawals of a payload.
pub type Withdrawals = ProgressiveList<Withdrawal>;

/// The accounts and storage slots a block touches, RLP-encoded, see EIP-7928.
pub type BlockAccessList = ProgressiveList<u8>;

/// Commitments to a payload's blobs.
pub type BlobKzgCommitments = ProgressiveList<KzgCommitment>;

/// Deposit requests of a payload.
pub type DepositRequests = ProgressiveList<DepositRequest>;

/// Withdrawal requests of a payload.
pub type WithdrawalRequests = ProgressiveList<WithdrawalRequest>;

/// Consolidation requests of a payload.
pub type ConsolidationRequests = ProgressiveList<ConsolidationRequest>;

/// Builder deposit requests of a payload.
pub type BuilderDepositRequests = ProgressiveList<BuilderDepositRequest>;

/// Builder exit requests of a payload.
pub type BuilderExitRequests = ProgressiveList<BuilderExitRequest>;

/// An execution block, as a builder reveals it.
///
/// See the Gloas beacon chain spec.
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
    pub transactions: Transactions,

    /// Withdrawals the consensus layer requested.
    pub withdrawals: Withdrawals,

    /// Blob gas used by the block.
    pub blob_gas_used: u64,

    /// Excess blob gas carried into the block, which sets the blob fee.
    pub excess_blob_gas: u64,

    /// Accounts and storage slots the block touches, see EIP-7928.
    pub block_access_list: BlockAccessList,

    /// Beacon slot the payload belongs to, see EIP-7843.
    pub slot_number: u64,
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
        Transactions::FIXED_SIZE,
        Withdrawals::FIXED_SIZE,
        u64::FIXED_SIZE,
        u64::FIXED_SIZE,
        BlockAccessList::FIXED_SIZE,
        u64::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true; 19]);

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
        visitor.field(&self.block_access_list);
        visitor.field(&self.slot_number);
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
            block_access_list: fields.field()?,
            slot_number: fields.field()?,
        })
    }
}

/// Requests the execution layer passes to the consensus layer.
///
/// See EIP-7685 and EIP-8282.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionRequests {
    /// Deposit requests, see EIP-6110.
    pub deposits: DepositRequests,

    /// Withdrawal requests, see EIP-7002.
    pub withdrawals: WithdrawalRequests,

    /// Consolidation requests, see EIP-7251.
    pub consolidations: ConsolidationRequests,

    /// Builder deposit requests.
    pub builder_deposits: BuilderDepositRequests,

    /// Builder exit requests.
    pub builder_exits: BuilderExitRequests,
}

impl Container for ExecutionRequests {
    const FIELDS: &'static [Option<usize>] = &[
        DepositRequests::FIXED_SIZE,
        WithdrawalRequests::FIXED_SIZE,
        ConsolidationRequests::FIXED_SIZE,
        BuilderDepositRequests::FIXED_SIZE,
        BuilderExitRequests::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true; 5]);

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.deposits);
        visitor.field(&self.withdrawals);
        visitor.field(&self.consolidations);
        visitor.field(&self.builder_deposits);
        visitor.field(&self.builder_exits);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            deposits: fields.field()?,
            withdrawals: fields.field()?,
            consolidations: fields.field()?,
            builder_deposits: fields.field()?,
            builder_exits: fields.field()?,
        })
    }
}

/// Everything the execution engine needs to validate a payload.
///
/// See the Gloas beacon chain spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewPayloadRequest<P: Preset> {
    /// The payload.
    pub execution_payload: ExecutionPayload<P>,

    /// Hashes of the payload's blob commitments.
    pub versioned_hashes: VersionedHashes<P>,

    /// Root of the parent beacon block, see EIP-4788.
    pub parent_beacon_block_root: Root,

    /// Requests the payload produced.
    pub execution_requests: ExecutionRequests,
}

impl<P: Preset> Container for NewPayloadRequest<P> {
    const FIELDS: &'static [Option<usize>] = &[
        <ExecutionPayload<P>>::FIXED_SIZE,
        <VersionedHashes<P>>::FIXED_SIZE,
        Root::FIXED_SIZE,
        ExecutionRequests::FIXED_SIZE,
    ];
    const MERKLEIZATION: Merkleization = Merkleization::Progressive(&[true; 4]);

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
