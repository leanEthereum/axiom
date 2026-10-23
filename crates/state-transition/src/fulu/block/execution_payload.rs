//! The execution payload step, under the blob schedule.

use axiom_types::{
    Preset,
    accessors::{CoreState, ExecutionHeaderState},
    deneb::ExecutionPayloadHeader,
    electra::{BeaconBlockBody, BlindedBeaconBlockBody, NewPayloadRequest},
};

use crate::{BlockError, BlockProcessor, ExecutionEngine, Fork, KnownVerdict, Operation, electra};

/// A block body's execution payload, with the engine that judges it, by Fulu's rule.
///
/// Fulu reads the blob limit from the blob schedule, see EIP-7892.
/// The rest of the step is Electra's.
#[derive(Debug)]
pub struct PayloadExecution<'a, P: Preset, E>(electra::block::PayloadExecution<'a, P, E>);

impl<'a, P: Preset, E> PayloadExecution<'a, P, E> {
    /// A body's payload, to be judged by an engine.
    pub const fn new(body: &'a BeaconBlockBody<P>, engine: &'a E) -> Self {
        Self(electra::block::PayloadExecution::new(body, engine))
    }
}

impl<'a, P: Preset> PayloadExecution<'a, P, KnownVerdict> {
    /// A blinded body's payload header, whose payload was pruned after its block was judged.
    #[must_use]
    pub const fn blinded(body: &'a BlindedBeaconBlockBody<P>) -> Self {
        Self(electra::block::PayloadExecution::blinded(body))
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
    /// Runs Electra's payload step under the blob limit the schedule sets for this epoch.
    ///
    /// See `process_execution_payload` in the Fulu beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let epoch = processor.state.beacon().current_epoch();
        let limit = processor.config.blob_parameters(epoch).max_blobs_per_block;
        self.0.execute(processor, limit)
    }
}
