//! The execution payload step: anchoring the execution chain in the beacon block.

use axiom_ssz::Ssz;
use axiom_types::{
    KzgCommitment, Preset,
    accessors::{CoreState, ExecutionHeaderState},
    deneb::ExecutionPayloadHeader,
    electra::{BeaconBlockBody, NewPayloadRequest},
};

use crate::{BlockError, BlockProcessor, ExecutionEngine, Fork, Operation, StateError};

/// A block body's execution payload, with the engine that judges it, by Electra's rule.
///
/// Electra hands the block's execution requests to the engine, and raised the blob limit.
/// See EIP-7685 and EIP-7691.
#[derive(Debug)]
pub struct PayloadExecution<'a, P: Preset, E> {
    /// The body carrying the payload, its blob commitments, and its requests.
    body: &'a BeaconBlockBody<P>,
    /// The execution engine.
    engine: &'a E,
}

impl<'a, P: Preset, E> PayloadExecution<'a, P, E> {
    /// A body's payload, to be judged by an engine.
    pub const fn new(body: &'a BeaconBlockBody<P>, engine: &'a E) -> Self {
        Self { body, engine }
    }

    /// Checks the payload under a blob limit, has the engine validate it, and caches its header.
    ///
    /// The payload must extend the latest payload, use the current randomness and timestamp,
    /// stay within the blob limit, and satisfy the engine.
    /// Fulu keeps this rule and changes only where the blob limit comes from.
    ///
    /// See `process_execution_payload` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when a check fails or the engine rejects the payload.
    pub fn execute<S>(
        &self,
        processor: &mut BlockProcessor<'_, S>,
        blob_limit: u64,
    ) -> Result<(), BlockError>
    where
        S: Fork<Preset = P>
            + ExecutionHeaderState<ExecutionPayloadHeader = ExecutionPayloadHeader<P>>,
        E: ExecutionEngine<NewPayloadRequest<P>>,
    {
        let body = self.body;
        let state = processor.state.beacon();
        let payload = &body.execution_payload;
        let epoch = state.current_epoch();

        let latest_hash = state.latest_execution_payload_header().block_hash;
        if payload.parent_hash != latest_hash {
            return Err(BlockError::PayloadParentMismatch {
                claimed: payload.parent_hash,
                expected: latest_hash,
            });
        }
        let randao_mix = state.randao_mix(epoch);
        if payload.prev_randao != randao_mix {
            return Err(BlockError::PayloadRandaoMismatch {
                claimed: payload.prev_randao,
                expected: randao_mix,
            });
        }
        // Timing: genesis time plus the slot's whole milliseconds, truncated to seconds.
        let slot_ms = state
            .slot()
            .0
            .checked_mul(processor.config.slot_duration_ms)
            .ok_or(StateError::Overflow {
                quantity: "slot time in milliseconds",
            })?;
        let expected_timestamp = state.genesis_time() + slot_ms / 1000;
        if payload.timestamp != expected_timestamp {
            return Err(BlockError::PayloadTimestampMismatch {
                claimed: payload.timestamp,
                expected: expected_timestamp,
            });
        }
        if body.blob_kzg_commitments.len() as u64 > blob_limit {
            return Err(BlockError::TooManyBlobs {
                count: body.blob_kzg_commitments.len(),
                limit: blob_limit,
            });
        }

        let request = NewPayloadRequest {
            execution_payload: payload.clone(),
            versioned_hashes: body.blob_kzg_commitments.map(KzgCommitment::versioned_hash),
            parent_beacon_block_root: state.latest_block_header().parent_root,
            execution_requests: body.execution_requests.clone(),
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

impl<S, E> Operation<S> for PayloadExecution<'_, <S as CoreState>::Preset, E>
where
    S: Fork
        + ExecutionHeaderState<
            ExecutionPayloadHeader = ExecutionPayloadHeader<<S as CoreState>::Preset>,
        >,
    E: ExecutionEngine<NewPayloadRequest<<S as CoreState>::Preset>>,
{
    /// Runs the payload step under Electra's fixed blob limit.
    ///
    /// See `process_execution_payload` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let limit = processor.config.max_blobs_per_block_electra;
        self.execute(processor, limit)
    }
}
