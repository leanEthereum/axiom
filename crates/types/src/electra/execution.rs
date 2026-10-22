//! Requests the execution layer passes to the consensus layer, see EIP-7685.

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};

use crate::{
    Preset, Root,
    electra::{
        ConsolidationRequest, DepositRequest, ExecutionPayload, VersionedHashes, WithdrawalRequest,
    },
};

/// Deposit requests of a payload.
pub type DepositRequests<P> = List<DepositRequest, <P as Preset>::MaxDepositRequestsPerPayload>;

/// Withdrawal requests of a payload.
pub type WithdrawalRequests<P> =
    List<WithdrawalRequest, <P as Preset>::MaxWithdrawalRequestsPerPayload>;

/// Consolidation requests of a payload.
pub type ConsolidationRequests<P> =
    List<ConsolidationRequest, <P as Preset>::MaxConsolidationRequestsPerPayload>;

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
