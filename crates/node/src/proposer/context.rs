//! What a proposal needs from the chain, read in one visit to the chain thread.

use axiom_block_production::{BlockProducer, ParentPayload, PayloadRequest, ProductionError};
use axiom_state_transition::State;
use axiom_types::{
    BlsPubkey, ForkName, Preset, Slot, ValidatorIndex,
    accessors::{BuilderState, CoreState, ForkState},
    gloas,
};

use crate::{Chain, ExecutionHead, ProposerError};

/// The head a proposal builds on, its proposer, and the payload it asks the engine for.
#[derive(Clone, Debug)]
pub(crate) struct ProposalContext<P: Preset> {
    /// The head's post-state, which the block extends.
    pub(crate) state: State<P>,
    /// The fork of the proposal's slot.
    pub(crate) fork: ForkName,
    /// The proposer the state elects.
    pub(crate) proposer: ValidatorIndex,
    /// The proposer's key.
    pub(crate) pubkey: BlsPubkey,
    /// Whether a Gloas block builds on its parent's payload.
    pub(crate) parent: ParentPayload,
    /// The execution head to build on and the build's inputs, once the merge is done.
    pub(crate) execution: Option<(ExecutionHead, PayloadRequest)>,
}

impl<P: Preset> ProposalContext<P> {
    /// Reads the context of a proposal at a slot from the chain.
    ///
    /// # Errors
    ///
    /// Fails when the slot is not after the head, or the head's state cannot reach it.
    pub(crate) fn gather(chain: &mut Chain<P>, slot: Slot) -> Result<Self, ProposerError> {
        let head = chain.head();
        if slot <= head.slot {
            return Err(ProposerError::SlotOutOfRange {
                slot,
                head: head.slot,
            });
        }
        let config = chain.config().clone();
        let fork = config.fork_at(slot.epoch::<P>());
        let state = chain.head_state()?.clone();
        let mut advanced = state.clone();
        advanced
            .process_slots(&config, slot)
            .map_err(|source| ProductionError::Slots { slot, source })?;
        let proposer = advanced
            .beacon_proposer_index()
            .map_err(|source| ProductionError::Proposer { slot, source })?;
        let pubkey = advanced
            .beacon()
            .validators()
            .get(proposer.as_usize())
            .map(|validator| validator.pubkey)
            .unwrap_or_default();

        // Gloas builds on the parent's payload only where fork choice says so.
        let builds_on_full = fork.separates_payloads() && chain.builds_on_full(slot)?;
        let parent = if builds_on_full {
            let requests = chain
                .database()
                .envelope(head.root)?
                .map(|envelope| envelope.message.execution_requests)
                .unwrap_or_default();
            ParentPayload::Full(requests)
        } else {
            ParentPayload::Empty
        };

        let execution = if advanced.beacon().is_merge_transition_complete() {
            // A Gloas payload extends the parent's payload, or the payload the parent extended.
            let head_hash = match gloas::BeaconState::<P>::from_any(advanced.beacon()) {
                Some(gloas) if builds_on_full => gloas.latest_execution_payload_bid().block_hash,
                Some(gloas) => gloas.latest_execution_payload_bid().parent_block_hash,
                None => head.execution.head,
            };
            let producer = BlockProducer::new(&config, chain.pool());
            let request = producer.payload_request(&state, slot, &parent)?;
            let execution_head = ExecutionHead {
                head: head_hash,
                ..head.execution
            };
            Some((execution_head, request))
        } else {
            None
        };
        Ok(Self {
            state,
            fork,
            proposer,
            pubkey,
            parent,
            execution,
        })
    }
}
