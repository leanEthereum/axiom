//! The execution payload step of Deneb: payloads that commit to blobs.

use axiom_ssz::Ssz;
use axiom_types::{
    KzgCommitment, Preset,
    accessors::{CoreState, ExecutionHeaderState},
    deneb::{BeaconBlockBody, ExecutionPayloadHeader, NewPayloadRequest},
};

use crate::{
    BlockError, BlockProcessor, ExecutionEngine, Fork, Operation, capella::block::PayloadAnchor,
};

/// A block body's execution payload, with the engine that judges it, by Deneb's rule.
///
/// Deneb bounds the blob commitments, and hands the engine their versioned hashes.
/// The engine also gets the parent beacon block root, see EIP-4788.
/// Electra added execution requests, in its own type.
#[derive(Debug)]
pub struct PayloadExecution<'a, P: Preset, E> {
    /// The body carrying the payload and its blob commitments.
    body: &'a BeaconBlockBody<P>,
    /// The execution engine.
    engine: &'a E,
}

impl<'a, P: Preset, E> PayloadExecution<'a, P, E> {
    /// A body's payload, to be judged by an engine.
    pub const fn new(body: &'a BeaconBlockBody<P>, engine: &'a E) -> Self {
        Self { body, engine }
    }
}

impl<S, E> Operation<S> for PayloadExecution<'_, <S as CoreState>::Preset, E>
where
    S: Fork
        + ExecutionHeaderState<
            ExecutionPayloadHeader = ExecutionPayloadHeader<<S as CoreState>::Preset>,
        >,
    E: ExecutionEngine<NewPayloadRequest<<S as CoreState>::Preset>>,
{
    /// Checks the payload against the chain, has the engine validate it, and caches its header.
    ///
    /// The payload must extend the latest payload at the current randomness and slot time.
    /// Its blobs must stay within the limit, and the engine must accept it.
    ///
    /// See `process_execution_payload` in the Deneb beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let body = self.body;
        let payload = &body.execution_payload;
        let state = processor.state.beacon();
        PayloadAnchor {
            parent_hash: payload.parent_hash,
            prev_randao: payload.prev_randao,
            timestamp: payload.timestamp,
        }
        .check(
            state,
            state.latest_execution_payload_header().block_hash,
            processor.config,
        )?;

        // Threshold: the fixed Deneb limit; Fulu moved it into the blob schedule.
        let limit = processor.config.max_blobs_per_block;
        if body.blob_kzg_commitments.len() as u64 > limit {
            return Err(BlockError::TooManyBlobs {
                count: body.blob_kzg_commitments.len(),
                limit,
            });
        }

        let request = NewPayloadRequest {
            execution_payload: payload.clone(),
            versioned_hashes: body.blob_kzg_commitments.map(KzgCommitment::versioned_hash),
            parent_beacon_block_root: state.latest_block_header().parent_root,
        };
        if !self.engine.verify_and_notify_new_payload(&request) {
            return Err(BlockError::PayloadInvalid(payload.block_hash));
        }

        *processor.state.beacon.latest_execution_payload_header_mut() = ExecutionPayloadHeader {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.hash_tree_root(),
            withdrawals_root: payload.withdrawals.hash_tree_root(),
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
        };
        Ok(())
    }
}
