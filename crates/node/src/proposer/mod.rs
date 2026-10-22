//! Proposing for the node's validators: payloads from the engine, blocks from the pool.

mod context;
mod engine_payload;
mod error;
mod preparation;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use axiom_block_production::{
    BlockProducer, ExecutionChoice, GloasBid, LocalBuild, PayloadRequest, ProducedBlock, Proposal,
    ProposalRequest, RandaoCheck,
};
use axiom_execution::PayloadId;
use axiom_ssz::Ssz;
use axiom_types::{
    BlsSignature, Bytes32, ExecutionAddress, Preset, Root, Slot, ValidatorIndex,
    bellatrix::ValidatorRegistrationV1, gloas::ExecutionPayloadEnvelope,
};
use context::ProposalContext;
pub use error::ProposerError;
use preparation::Preparations;
use tracing::{debug, warn};

use self::engine_payload::{BuildOrder, EnginePayload};
use crate::{ChainHandle, ExecutionHead, ExecutionLayer};

/// What a validator client asks for when it proposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockOrder {
    /// The slot to propose in.
    pub slot: Slot,
    /// The proposer's signature over the slot's epoch.
    pub randao_reveal: BlsSignature,
    /// Free-form bytes for the block.
    pub graffiti: Bytes32,
    /// Whether to check the reveal before building on it.
    pub randao: RandaoCheck,
}

/// The node's proposal desk: payload preparation, block production, and their caches.
///
/// # Overview
///
/// 1. Validators name their fee recipients ahead of their slots.
/// 2. Before a prepared validator's slot, the engine starts building on the head.
/// 3. At the slot, the payload comes back and the pool's operations join it in a block.
///
/// A self-built Gloas payload waits here for its envelope to be fetched and signed.
#[derive(Debug)]
pub struct ProposerService<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The execution engine.
    execution: Arc<ExecutionLayer>,
    /// Fee recipients and registrations.
    preparations: Mutex<Preparations>,
    /// Builds started ahead of their slot, by slot and parent root.
    builds: Mutex<HashMap<(Slot, Root), PayloadId>>,
    /// The envelope of the latest self-built Gloas block, by slot and block root.
    envelope: Mutex<Option<(Slot, Root, ExecutionPayloadEnvelope<P>)>>,
}

impl<P: Preset> ProposerService<P> {
    /// A desk over the chain and the engine, paying a default fee recipient.
    #[must_use]
    pub fn new(
        chain: ChainHandle<P>,
        execution: Arc<ExecutionLayer>,
        default_fee_recipient: ExecutionAddress,
    ) -> Self {
        Self {
            chain,
            execution,
            preparations: Mutex::new(Preparations::new(default_fee_recipient)),
            builds: Mutex::new(HashMap::new()),
            envelope: Mutex::new(None),
        }
    }

    /// Records the fee recipients validators named for their coming proposals.
    pub fn prepare(
        &self,
        recipients: impl IntoIterator<Item = (ValidatorIndex, ExecutionAddress)>,
    ) {
        let mut preparations = self.preparations();
        for (validator, fee_recipient) in recipients {
            preparations.prepare(validator, fee_recipient);
        }
    }

    /// Records the builder registrations validators signed.
    pub fn register(&self, registrations: impl IntoIterator<Item = ValidatorRegistrationV1>) {
        let mut preparations = self.preparations();
        for registration in registrations {
            preparations.register(registration);
        }
    }

    /// Starts the engine building the payload of the next slot, when its proposer prepared.
    ///
    /// Building ahead gives the engine the whole slot to fill the payload.
    pub async fn prepare_next(&self, slot: Slot) {
        let gathered = self
            .chain
            .run(move |chain| ProposalContext::gather(chain, slot))
            .await;
        let Ok(Ok(context)) = gathered else {
            return;
        };
        if !self.preparations().is_prepared(context.proposer) {
            return;
        }
        let Some((head, request)) = context.execution.clone() else {
            return;
        };
        let parent_root = request.parent_beacon_block_root;
        let order = self.build_order(&context, request);
        let Some(attributes) = order.attributes::<P>(context.fork) else {
            return;
        };
        match self
            .execution
            .start_build(context.fork, head, &attributes)
            .await
        {
            Ok(Some(id)) => {
                debug!(%slot, "engine building ahead of the slot");
                self.builds().insert((slot, parent_root), id);
            }
            Ok(None) => debug!(%slot, "engine started no build ahead of the slot"),
            Err(error) => warn!(%slot, %error, "could not prepare the payload"),
        }
    }

    /// Produces the unsigned block of a slot on the current head.
    ///
    /// # Errors
    ///
    /// Fails when the slot is not after the head, the engine fails, or the block is invalid.
    pub async fn produce(&self, order: BlockOrder) -> Result<Proposal<P>, ProposerError> {
        let slot = order.slot;
        let context = self
            .chain
            .run(move |chain| ProposalContext::gather(chain, slot))
            .await??;
        let execution = match context.execution.clone() {
            None => ExecutionChoice::PreMerge,
            Some((head, request)) => {
                let build = self.local_build(&context, head, request).await?;
                if context.fork.separates_payloads() {
                    ExecutionChoice::Gloas {
                        parent: context.parent.clone(),
                        bid: GloasBid::SelfBuild(Box::new(build)),
                    }
                } else {
                    ExecutionChoice::Local(build)
                }
            }
        };
        let request = ProposalRequest {
            slot,
            randao_reveal: order.randao_reveal,
            randao: order.randao,
            graffiti: order.graffiti,
            eth1_chain: Vec::new(),
            deposits: Vec::new(),
            execution,
        };
        let state = context.state;
        let proposal = self
            .chain
            .run(move |chain| {
                BlockProducer::new(chain.config(), chain.pool()).produce(&state, request)
            })
            .await??;
        if let ProducedBlock::GloasContents(contents) = &proposal.block {
            let root = contents.block.hash_tree_root();
            let envelope = contents.execution_payload_envelope.clone();
            *self.envelope.lock().unwrap_or_else(PoisonError::into_inner) =
                Some((slot, root, envelope));
        }
        Ok(proposal)
    }

    /// The envelope of the self-built Gloas block at a slot, when the node built it.
    #[must_use]
    pub fn envelope(&self, slot: Slot, block_root: Root) -> Option<ExecutionPayloadEnvelope<P>> {
        let cached = self.envelope.lock().unwrap_or_else(PoisonError::into_inner);
        cached
            .as_ref()
            .filter(|(cached_slot, root, _)| *cached_slot == slot && *root == block_root)
            .map(|(_, _, envelope)| envelope.clone())
    }

    /// The payload the engine built for a proposal, from the build started ahead when there is one.
    async fn local_build(
        &self,
        context: &ProposalContext<P>,
        head: ExecutionHead,
        request: PayloadRequest,
    ) -> Result<LocalBuild<P>, ProposerError> {
        let slot = request.slot;
        let key = (slot, request.parent_beacon_block_root);
        let prepared = self.builds().remove(&key);
        let id = match prepared {
            Some(id) => id,
            None => {
                let order = self.build_order(context, request);
                let attributes = order
                    .attributes::<P>(context.fork)
                    .ok_or(ProposerError::NoBuild(slot))?;
                self.execution
                    .start_build(context.fork, head, &attributes)
                    .await?
                    .ok_or(ProposerError::NoBuild(slot))?
            }
        };
        let response = self.execution.fetch_payload::<P>(context.fork, id).await?;
        Ok(EnginePayload::local_build(response))
    }

    /// The build order of a proposal, with the proposer's fee recipient and gas limit.
    fn build_order(&self, context: &ProposalContext<P>, request: PayloadRequest) -> BuildOrder {
        let preparations = self.preparations();
        BuildOrder {
            request,
            fee_recipient: preparations.fee_recipient(context.proposer, &context.pubkey),
            gas_limit: preparations.gas_limit(&context.pubkey),
        }
    }

    /// The preparations, through a lock no holder can poison for good.
    fn preparations(&self) -> MutexGuard<'_, Preparations> {
        self.preparations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The builds started ahead, through the same kind of lock.
    fn builds(&self) -> MutexGuard<'_, HashMap<(Slot, Root), PayloadId>> {
        self.builds.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
