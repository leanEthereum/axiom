//! The execution payload step of Capella: payloads that carry withdrawals.

use axiom_types::{
    Preset,
    accessors::{CoreState, ExecutionHeaderState},
    capella::{ExecutionPayload, ExecutionPayloadHeader, NewPayloadRequest},
};

use crate::{
    BlockError, BlockProcessor, ExecutionEngine, Fork, KnownVerdict, Operation, PayloadPart,
    capella::block::PayloadAnchor,
};

/// An execution payload, with the engine that judges it, by Capella's rule.
///
/// Capella dropped the merge checks, since every chain had merged.
/// Deneb added blobs, in its own type.
#[derive(Debug)]
pub struct PayloadExecution<'a, P: Preset, E> {
    /// The payload, or its header once pruned.
    payload: PayloadPart<'a, ExecutionPayload<P>, ExecutionPayloadHeader<P>>,
    /// The execution engine.
    engine: &'a E,
}

impl<'a, P: Preset, E> PayloadExecution<'a, P, E> {
    /// A payload, to be judged by an engine.
    pub const fn new(payload: &'a ExecutionPayload<P>, engine: &'a E) -> Self {
        Self {
            payload: PayloadPart::Full(payload),
            engine,
        }
    }
}

impl<'a, P: Preset> PayloadExecution<'a, P, KnownVerdict> {
    /// A payload header, whose payload was pruned after its block was judged.
    #[must_use]
    pub const fn blinded(header: &'a ExecutionPayloadHeader<P>) -> Self {
        Self {
            payload: PayloadPart::Header(header),
            engine: &KnownVerdict(true),
        }
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
    /// A pruned payload is checked through its header, and not sent to the engine.
    /// See `process_execution_payload` in the Capella beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let header = self.payload.header();
        let state = processor.state.beacon();
        PayloadAnchor {
            parent_hash: header.parent_hash,
            prev_randao: header.prev_randao,
            timestamp: header.timestamp,
        }
        .check(
            state,
            state.latest_execution_payload_header().block_hash,
            processor.config,
        )?;

        if let Some(payload) = self.payload.full() {
            let request = NewPayloadRequest {
                execution_payload: payload.clone(),
            };
            if !self.engine.verify_and_notify_new_payload(&request) {
                return Err(BlockError::PayloadInvalid(payload.block_hash));
            }
        }

        *processor.state.beacon.latest_execution_payload_header_mut() = header;
        Ok(())
    }
}
