//! The execution payload step: anchoring the execution chain in the beacon block.

use axiom_ssz::Ssz;
use axiom_types::{
    BeaconBlockBody, ExecutionPayloadHeader, KzgCommitment, NewPayloadRequest, Preset,
};

use super::BlockProcessor;
use crate::{BlockError, ExecutionEngine, StateError};

impl<P: Preset> BlockProcessor<'_, P> {
    /// Checks the payload against the chain, has the engine validate it, and caches its header.
    ///
    /// See `process_execution_payload` in the Fulu beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the payload does not extend the latest payload, uses the wrong randomness,
    /// has the wrong timestamp, carries too many blobs, or the engine rejects it.
    pub fn process_execution_payload(
        &mut self,
        body: &BeaconBlockBody<P>,
        engine: &impl ExecutionEngine<P>,
    ) -> Result<(), BlockError> {
        let state = &self.state.beacon;
        let payload = &body.execution_payload;
        let epoch = state.current_epoch();

        if payload.parent_hash != state.latest_execution_payload_header.block_hash {
            return Err(BlockError::PayloadParentMismatch);
        }
        if payload.prev_randao != state.randao_mix(epoch) {
            return Err(BlockError::PayloadRandaoMismatch);
        }
        // Timing: genesis time plus the slot's whole milliseconds, truncated to seconds.
        let slot_ms = state
            .slot
            .0
            .checked_mul(self.config.slot_duration_ms)
            .ok_or(StateError::Overflow)?;
        let expected_timestamp = state.genesis_time + slot_ms / 1000;
        if payload.timestamp != expected_timestamp {
            return Err(BlockError::PayloadTimestampMismatch);
        }
        let limit = self.config.blob_parameters(epoch).max_blobs_per_block;
        if body.blob_kzg_commitments.len() as u64 > limit {
            return Err(BlockError::TooManyBlobs {
                count: body.blob_kzg_commitments.len(),
                limit,
            });
        }

        let request = NewPayloadRequest {
            execution_payload: payload.clone(),
            versioned_hashes: body.blob_kzg_commitments.map(KzgCommitment::versioned_hash),
            parent_beacon_block_root: state.latest_block_header.parent_root,
            execution_requests: body.execution_requests.clone(),
        };
        if !engine.verify_and_notify_new_payload(&request) {
            return Err(BlockError::PayloadInvalid);
        }

        self.state.beacon.latest_execution_payload_header = ExecutionPayloadHeader {
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
