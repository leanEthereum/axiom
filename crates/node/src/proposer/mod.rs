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
    BlockProducer, BuilderBoost, ExecutionChoice, GloasBid, LocalBuild, PayloadRequest,
    ProducedBlock, Proposal, ProposalRequest, RandaoCheck, Wei,
};
use axiom_builder_client::{
    BidRequest, CircuitBreaker, GasLimitTarget, RelaySet, UnblindedBlock, VerifiedBid,
};
use axiom_execution::PayloadId;
use axiom_operation_pool::BidPool;
use axiom_ssz::Ssz;
use axiom_types::{
    BlsSignature, Bytes32, ExecutionAddress, Preset, Root, Slot, ValidatorIndex,
    bellatrix::{SignedValidatorRegistrationV1, ValidatorRegistrationV1},
    combined::SignedBlindedBeaconBlock,
    gloas::ExecutionPayloadEnvelope,
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
    /// How strongly the proposer prefers a builder's payload over its own.
    pub boost: BuilderBoost,
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
    /// Builders that sell payloads, when any are configured.
    relays: Option<RelaySet>,
    /// When the chain is too unhealthy to trust builders with a slot.
    breaker: CircuitBreaker,
    /// Graffiti of blocks whose request names none.
    graffiti: Bytes32,
    /// Whether payloads are prepared for every slot, not only for prepared proposers.
    always_prepare: bool,
}

impl<P: Preset> ProposerService<P> {
    /// A desk over the chain, the engine, and the builders, paying a default fee recipient.
    #[must_use]
    pub fn new(
        chain: ChainHandle<P>,
        execution: Arc<ExecutionLayer>,
        default_fee_recipient: ExecutionAddress,
        relays: Option<RelaySet>,
    ) -> Self {
        Self {
            chain,
            execution,
            preparations: Mutex::new(Preparations::new(default_fee_recipient)),
            builds: Mutex::new(HashMap::new()),
            envelope: Mutex::new(None),
            relays,
            breaker: CircuitBreaker::for_preset::<P>(),
            graffiti: Bytes32::default(),
            always_prepare: false,
        }
    }

    /// Closes the builder path under other thresholds than the preset's defaults.
    #[must_use]
    pub const fn with_breaker(mut self, breaker: CircuitBreaker) -> Self {
        self.breaker = breaker;
        self
    }

    /// Writes this graffiti into blocks whose request names none.
    #[must_use]
    pub const fn with_graffiti(mut self, graffiti: Bytes32) -> Self {
        self.graffiti = graffiti;
        self
    }

    /// Prepares a payload for every slot, paying the default fee recipient when nobody prepared.
    ///
    /// Builders and relays use it to watch every slot's payload attributes.
    #[must_use]
    pub const fn preparing_always(mut self) -> Self {
        self.always_prepare = true;
        self
    }

    /// Graffiti of blocks whose request names none.
    #[must_use]
    pub const fn graffiti(&self) -> Bytes32 {
        self.graffiti
    }

    /// Records builder registrations, and forwards them to every builder.
    ///
    /// A builder that fails is logged; the others still learn the registrations.
    pub async fn register_with_builders(&self, registrations: &[SignedValidatorRegistrationV1]) {
        self.register(registrations.iter().map(|signed| signed.message.clone()));
        let Some(relays) = &self.relays else {
            return;
        };
        for failure in relays.register_validators(registrations).await {
            warn!(relay = %failure.relay, error = %failure.error, "builder refused registrations");
        }
    }

    /// Asks the builder that sold a blinded block's payload to reveal it.
    ///
    /// # Errors
    ///
    /// Fails when no builder is configured, or none reveals a payload matching the block.
    pub async fn reveal(
        &self,
        block: &SignedBlindedBeaconBlock<P>,
    ) -> Result<UnblindedBlock<P>, ProposerError> {
        let relays = self.relays.as_ref().ok_or(ProposerError::NoBuilder)?;
        relays
            .submit_blinded_block(block)
            .await
            .map_err(ProposerError::Builder)
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
        if !self.always_prepare && !self.preparations().is_prepared(context.proposer) {
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
        let (execution, fallback) = match context.execution.clone() {
            None => (ExecutionChoice::PreMerge, None),
            Some((head, request)) => {
                let bid = self.builder_bid(&context, head, &request).await;
                let build = self.local_build(&context, head, request).await;
                Self::choose(&context, order.boost, build, bid)?
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
                let producer = BlockProducer::new(chain.config(), chain.pool());
                match (producer.produce(&state, request.clone()), fallback) {
                    // A builder's bid the state refuses, say for want of balance, falls back.
                    (Err(error), Some(execution)) => {
                        warn!(%error, "builder bid refused; building the payload locally");
                        producer.produce(
                            &state,
                            ProposalRequest {
                                execution,
                                ..request
                            },
                        )
                    }
                    (outcome, _) => outcome,
                }
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

    /// The payload a block commits to: the engine's, or a builder's when it pays enough more.
    ///
    /// A failed local build still leaves a builder's bid, and a missing bid the local build.
    ///
    /// # Returns
    ///
    /// The choice, and the self-built payload to fall back on when a Gloas bid fails its checks.
    fn choose(
        context: &ProposalContext<P>,
        boost: BuilderBoost,
        build: Result<LocalBuild<P>, ProposerError>,
        bid: Option<VerifiedBid<P>>,
    ) -> Result<(ExecutionChoice<P>, Option<ExecutionChoice<P>>), ProposerError> {
        if context.fork.separates_payloads() {
            // A gossiped bid wins when, boosted, it pays more than the engine's payload.
            // See the bid comparison of the block production route in beacon-APIs.
            let local = build?;
            let parent = context.parent.clone();
            let self_build = |local| ExecutionChoice::Gloas {
                parent: parent.clone(),
                bid: GloasBid::SelfBuild(Box::new(local)),
            };
            return Ok(match &context.gloas_bid {
                Some(bid)
                    if boost
                        .prefers_builder(local.value, Wei::from_gwei(BidPool::total(bid).0)) =>
                {
                    let chosen = ExecutionChoice::Gloas {
                        parent: context.parent.clone(),
                        bid: GloasBid::Builder(Box::new(bid.clone())),
                    };
                    (chosen, Some(self_build(local)))
                }
                _ => (self_build(local), None),
            });
        }
        let chosen = match (build, bid) {
            (Ok(local), Some(bid)) if boost.prefers_builder(local.value, bid.value()) => {
                ExecutionChoice::Builder(bid.into_bid())
            }
            (Ok(local), _) => ExecutionChoice::Local(local),
            (Err(error), Some(bid)) => {
                warn!(%error, "local payload failed; using the builder's");
                ExecutionChoice::Builder(bid.into_bid())
            }
            (Err(error), None) => return Err(error),
        };
        Ok((chosen, None))
    }

    /// The best verified bid of the configured builders, when the fork and the chain allow one.
    async fn builder_bid(
        &self,
        context: &ProposalContext<P>,
        head: ExecutionHead,
        request: &PayloadRequest,
    ) -> Option<VerifiedBid<P>> {
        let relays = self.relays.as_ref()?;
        if !context.fork.has_builder_api() {
            return None;
        }
        if let Err(trip) = self.breaker.check::<P>(&context.health) {
            warn!(%trip, "chain unhealthy; building locally");
            return None;
        }
        let bid_request = BidRequest {
            fork: context.fork,
            slot: request.slot,
            parent_hash: head.head,
            proposer: context.pubkey,
            timestamp: request.timestamp,
            prev_randao: request.prev_randao,
            gas_limit: GasLimitTarget {
                parent: context.parent_gas_limit,
                target: self.preparations().gas_limit(&context.pubkey),
            },
            withdrawals_root: request.withdrawals_root,
        };
        let config = self.chain.run(|chain| chain.config().clone()).await.ok()?;
        let auction = relays.best_header::<P>(&bid_request, &config).await;
        for failure in &auction.failures {
            debug!(relay = %failure.relay, error = %failure.error, "builder gave no usable bid");
        }
        auction.winner.map(|winner| winner.bid)
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
