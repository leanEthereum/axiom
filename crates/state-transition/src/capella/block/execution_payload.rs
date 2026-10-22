//! The execution payload step of Capella: payloads that carry withdrawals.

use axiom_ssz::Ssz;
use axiom_types::{
    Preset,
    accessors::{CoreState, ExecutionHeaderState},
    capella::{ExecutionPayload, ExecutionPayloadHeader, NewPayloadRequest},
};

use crate::{
    BlockError, BlockProcessor, ExecutionEngine, Fork, Operation, capella::block::PayloadAnchor,
};

/// An execution payload, with the engine that judges it, by Capella's rule.
///
/// Capella dropped the merge checks, since every chain had merged.
/// Deneb added blobs, in its own type.
#[derive(Debug)]
pub struct PayloadExecution<'a, P: Preset, E> {
    /// The payload.
    payload: &'a ExecutionPayload<P>,
    /// The execution engine.
    engine: &'a E,
}

impl<'a, P: Preset, E> PayloadExecution<'a, P, E> {
    /// A payload, to be judged by an engine.
    pub const fn new(payload: &'a ExecutionPayload<P>, engine: &'a E) -> Self {
        Self { payload, engine }
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
    /// See `process_execution_payload` in the Capella beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let payload = self.payload;
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

        let request = NewPayloadRequest {
            execution_payload: payload.clone(),
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
        };
        Ok(())
    }
}
