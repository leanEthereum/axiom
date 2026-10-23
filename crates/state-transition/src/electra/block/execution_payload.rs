//! The execution payload step: anchoring the execution chain in the beacon block.

use axiom_types::{
    KzgCommitment, Preset,
    accessors::{CoreState, ExecutionHeaderState},
    deneb::{BlobKzgCommitments, ExecutionPayload, ExecutionPayloadHeader},
    electra::{BeaconBlockBody, BlindedBeaconBlockBody, ExecutionRequests, NewPayloadRequest},
};

use crate::{
    BlockError, BlockProcessor, ExecutionEngine, Fork, KnownVerdict, Operation, PayloadPart,
    capella::block::PayloadAnchor,
};

/// A block body's execution payload, with the engine that judges it, by Electra's rule.
///
/// Electra hands the block's execution requests to the engine, and raised the blob limit.
/// See EIP-7685 and EIP-7691.
#[derive(Debug)]
pub struct PayloadExecution<'a, P: Preset, E> {
    /// The payload, or its header once pruned.
    payload: PayloadPart<'a, ExecutionPayload<P>, ExecutionPayloadHeader<P>>,
    /// The blob commitments of the body.
    commitments: &'a BlobKzgCommitments<P>,
    /// The execution requests of the body.
    requests: &'a ExecutionRequests<P>,
    /// The execution engine.
    engine: &'a E,
}

impl<'a, P: Preset, E> PayloadExecution<'a, P, E> {
    /// A body's payload, to be judged by an engine.
    pub const fn new(body: &'a BeaconBlockBody<P>, engine: &'a E) -> Self {
        Self {
            payload: PayloadPart::Full(&body.execution_payload),
            commitments: &body.blob_kzg_commitments,
            requests: &body.execution_requests,
            engine,
        }
    }

    /// Checks the payload under a blob limit, has the engine validate it, and caches its header.
    ///
    /// The payload must extend the latest payload, use the current randomness and timestamp,
    /// stay within the blob limit, and satisfy the engine when held whole.
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
        if self.commitments.len() as u64 > blob_limit {
            return Err(BlockError::TooManyBlobs {
                count: self.commitments.len(),
                limit: blob_limit,
            });
        }

        if let Some(payload) = self.payload.full() {
            let request = NewPayloadRequest {
                execution_payload: payload.clone(),
                versioned_hashes: self.commitments.map(KzgCommitment::versioned_hash),
                parent_beacon_block_root: state.latest_block_header().parent_root,
                execution_requests: self.requests.clone(),
            };
            if !self.engine.verify_and_notify_new_payload(&request) {
                return Err(BlockError::PayloadInvalid(payload.block_hash));
            }
        }

        *processor.state.beacon.latest_execution_payload_header_mut() = header;
        Ok(())
    }
}

impl<'a, P: Preset> PayloadExecution<'a, P, KnownVerdict> {
    /// A blinded body's payload header, whose payload was pruned after its block was judged.
    #[must_use]
    pub const fn blinded(body: &'a BlindedBeaconBlockBody<P>) -> Self {
        Self {
            payload: PayloadPart::Header(&body.execution_payload_header),
            commitments: &body.blob_kzg_commitments,
            requests: &body.execution_requests,
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
    /// Runs the payload step under Electra's fixed blob limit.
    ///
    /// See `process_execution_payload` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let limit = processor.config.max_blobs_per_block_electra;
        self.execute(processor, limit)
    }
}
