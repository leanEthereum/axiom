//! The execution payload step of Deneb: payloads that commit to blobs.

use axiom_types::{
    KzgCommitment, Preset,
    accessors::{CoreState, ExecutionHeaderState},
    deneb::{
        BeaconBlockBody, BlindedBeaconBlockBody, BlobKzgCommitments, ExecutionPayload,
        ExecutionPayloadHeader, NewPayloadRequest,
    },
};

use crate::{
    BlockError, BlockProcessor, ExecutionEngine, Fork, KnownVerdict, Operation, PayloadPart,
    capella::block::PayloadAnchor,
};

/// A block body's execution payload, with the engine that judges it, by Deneb's rule.
///
/// Deneb bounds the blob commitments, and hands the engine their versioned hashes.
/// The engine also gets the parent beacon block root, see EIP-4788.
/// Electra added execution requests, in its own type.
#[derive(Debug)]
pub struct PayloadExecution<'a, P: Preset, E> {
    /// The payload, or its header once pruned.
    payload: PayloadPart<'a, ExecutionPayload<P>, ExecutionPayloadHeader<P>>,
    /// The blob commitments of the body.
    commitments: &'a BlobKzgCommitments<P>,
    /// The execution engine.
    engine: &'a E,
}

impl<'a, P: Preset, E> PayloadExecution<'a, P, E> {
    /// A body's payload, to be judged by an engine.
    pub const fn new(body: &'a BeaconBlockBody<P>, engine: &'a E) -> Self {
        Self {
            payload: PayloadPart::Full(&body.execution_payload),
            commitments: &body.blob_kzg_commitments,
            engine,
        }
    }
}

impl<'a, P: Preset> PayloadExecution<'a, P, KnownVerdict> {
    /// A blinded body's payload header, whose payload was pruned after its block was judged.
    #[must_use]
    pub const fn blinded(body: &'a BlindedBeaconBlockBody<P>) -> Self {
        Self {
            payload: PayloadPart::Header(&body.execution_payload_header),
            commitments: &body.blob_kzg_commitments,
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
    /// The payload must extend the latest payload at the current randomness and slot time.
    /// Its blobs must stay within the limit, and the engine must accept it when held whole.
    ///
    /// See `process_execution_payload` in the Deneb beacon chain spec.
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

        // Threshold: the fixed Deneb limit; Fulu moved it into the blob schedule.
        let limit = processor.config.max_blobs_per_block;
        if self.commitments.len() as u64 > limit {
            return Err(BlockError::TooManyBlobs {
                count: self.commitments.len(),
                limit,
            });
        }

        if let Some(payload) = self.payload.full() {
            let request = NewPayloadRequest {
                execution_payload: payload.clone(),
                versioned_hashes: self.commitments.map(KzgCommitment::versioned_hash),
                parent_beacon_block_root: state.latest_block_header().parent_root,
            };
            if !self.engine.verify_and_notify_new_payload(&request) {
                return Err(BlockError::PayloadInvalid(payload.block_hash));
            }
        }

        *processor.state.beacon.latest_execution_payload_header_mut() = header;
        Ok(())
    }
}
