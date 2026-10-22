//! The execution payload step, through the merge with the execution chain.

use axiom_ssz::Ssz;
use axiom_types::{
    Preset,
    accessors::{CoreState, ExecutionHeaderState},
    bellatrix::{BeaconBlockBody, ExecutionPayload, ExecutionPayloadHeader, NewPayloadRequest},
};

use crate::{BlockError, BlockProcessor, ExecutionEngine, Fork, Operation, StateError};

/// A block body's execution payload, with the engine that judges it, by Bellatrix's rule.
///
/// Before the merge, the state's payload header is empty and blocks may carry an empty payload.
/// The first block with a payload completes the merge, and every block after must carry one.
/// Capella dropped the merge rules, since every Capella chain has merged.
#[derive(Debug)]
pub struct PayloadExecution<'a, P: Preset, E> {
    /// The body carrying the payload.
    body: &'a BeaconBlockBody<P>,
    /// The execution engine.
    engine: &'a E,
}

impl<'a, P: Preset, E> PayloadExecution<'a, P, E> {
    /// A body's payload, to be judged by an engine.
    pub const fn new(body: &'a BeaconBlockBody<P>, engine: &'a E) -> Self {
        Self { body, engine }
    }

    /// Whether the merge is done: the chain already accepted a payload.
    ///
    /// See `is_merge_transition_complete` in the Bellatrix beacon chain spec.
    #[must_use]
    pub fn is_merge_transition_complete(latest: &ExecutionPayloadHeader<P>) -> bool {
        *latest != ExecutionPayloadHeader::default()
    }

    /// Whether this payload completes the merge: the first one the chain sees.
    ///
    /// See `is_merge_transition_block` in the Bellatrix beacon chain spec.
    #[must_use]
    pub fn is_merge_transition_block(&self, latest: &ExecutionPayloadHeader<P>) -> bool {
        !Self::is_merge_transition_complete(latest)
            && self.body.execution_payload != ExecutionPayload::default()
    }

    /// Whether the block's payload is processed: after the merge, or in the block making it.
    ///
    /// See `is_execution_enabled` in the Bellatrix beacon chain spec.
    #[must_use]
    pub fn is_execution_enabled(&self, latest: &ExecutionPayloadHeader<P>) -> bool {
        Self::is_merge_transition_complete(latest) || self.is_merge_transition_block(latest)
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
    /// # Algorithm
    ///
    /// 1. After the merge, the payload must extend the latest payload.
    /// 2. It must use the current randao mix and the slot's start time.
    /// 3. The engine must accept it.
    /// 4. Its header becomes the latest, which completes the merge if it was pending.
    ///
    /// See `process_execution_payload` in the Bellatrix beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let state = processor.state.beacon();
        let payload = &self.body.execution_payload;

        // The merge block's parent is the terminal proof-of-work block, which fork choice checks.
        let latest = state.latest_execution_payload_header();
        if Self::is_merge_transition_complete(latest) && payload.parent_hash != latest.block_hash {
            return Err(BlockError::PayloadParentMismatch {
                claimed: payload.parent_hash,
                expected: latest.block_hash,
            });
        }
        let randao_mix = state.randao_mix(state.current_epoch());
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
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Hash32, Minimal};

    use super::*;
    use crate::KnownVerdict;

    #[test]
    fn execution_starts_with_the_first_payload_and_never_stops() {
        // Fixture: an empty body and a body whose payload names block number 1.
        let empty = BeaconBlockBody::<Minimal>::default();
        let mut carrying = BeaconBlockBody::<Minimal>::default();
        carrying.execution_payload.block_number = 1;
        let engine = KnownVerdict(true);

        // Before the merge: an empty payload is skipped, a non-empty one is the merge block.
        let unmerged = ExecutionPayloadHeader::<Minimal>::default();
        let skipped = PayloadExecution::new(&empty, &engine);
        let merging = PayloadExecution::new(&carrying, &engine);
        assert!(!skipped.is_execution_enabled(&unmerged));
        assert!(merging.is_merge_transition_block(&unmerged));
        assert!(merging.is_execution_enabled(&unmerged));

        // After the merge: every block runs its payload, even an empty one, and none merges.
        let merged = ExecutionPayloadHeader::<Minimal> {
            block_hash: Hash32([7; 32]),
            ..Default::default()
        };
        assert!(skipped.is_execution_enabled(&merged));
        assert!(!merging.is_merge_transition_block(&merged));
    }
}
