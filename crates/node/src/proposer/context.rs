//! What a proposal needs from the chain, read in one visit to the chain thread.

use std::collections::BTreeSet;

use axiom_block_production::{
    BlockProducer, ParentPayload, PayloadRequest, ProductionError, RevealedRequests,
};
use axiom_builder_client::ChainHealth;
use axiom_state_transition::State;
use axiom_types::{
    BlsPubkey, ForkName, Hash32, Preset, Root, Slot, ValidatorIndex, accessors::CoreState,
    combined, gloas::SignedExecutionPayloadBid,
};

use super::ProposerReorgs;
use crate::{Chain, ChainError, ExecutionHead, ProposerError};

/// The block a proposal builds on, its proposer, and the payload it asks the engine for.
#[derive(Clone, Debug)]
pub(crate) struct ProposalContext<P: Preset> {
    /// The post-state of the block the proposal extends: the head, or a late head's parent.
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
    /// Gas limit of the parent's payload, which a builder's bid must move from.
    pub(crate) parent_gas_limit: u64,
    /// The recent chain, which decides whether builders may be trusted with the slot.
    pub(crate) health: ChainHealth,
    /// The best bid gossip brought for a Gloas payload on this parent.
    pub(crate) gloas_bid: Option<SignedExecutionPayloadBid>,
}

impl<P: Preset> ProposalContext<P> {
    /// Reads the context of a proposal at a slot from the chain.
    ///
    /// The proposal extends the head, or the parent of a late head when reorgs are on.
    ///
    /// # Errors
    ///
    /// Fails when the slot is not after the head, or the parent's state cannot reach it.
    pub(crate) fn gather(
        chain: &mut Chain<P>,
        slot: Slot,
        reorgs: ProposerReorgs,
    ) -> Result<Self, ProposerError> {
        let head = chain.head();
        if slot <= head.slot {
            return Err(ProposerError::SlotOutOfRange {
                slot,
                head: head.slot,
            });
        }
        let extended = reorgs.parent(chain, slot)?;
        let config = chain.config().clone();
        let fork = config.fork_at(slot.epoch::<P>());
        let state = chain
            .store()
            .block_state(&extended.root)
            .ok_or(ChainError::MissingState(extended.root))?
            .clone();
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
        let builds_on_full = fork.separates_payloads() && chain.builds_on_full(extended, slot)?;
        let parent = if builds_on_full {
            let requests = chain
                .database()
                .envelope(extended.root)?
                .map(|envelope| envelope.message.execution_requests)
                .unwrap_or_default();
            ParentPayload::Full(RevealedRequests::Gloas(requests))
        } else {
            ParentPayload::Empty
        };

        let execution = if advanced.beacon().is_merge_transition_complete() {
            // A Gloas payload extends the parent's payload, or the payload the parent extended.
            // Earlier, the block's post-state records the latest payload hash.
            let head_hash = match advanced.beacon().builders() {
                Some(builders) if builds_on_full => {
                    builders.latest_execution_payload_bid().block_hash
                }
                Some(builders) => builders.latest_execution_payload_bid().parent_block_hash,
                None => state
                    .beacon()
                    .latest_execution_block_hash()
                    .unwrap_or(Hash32::ZERO),
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
        let gloas_bid = execution.as_ref().and_then(|(execution_head, _)| {
            chain
                .pool()
                .bids()
                .best(slot, extended.root, execution_head.head)
                .cloned()
        });
        let parent_gas_limit = Self::latest_gas_limit(state.beacon());
        let health = Self::health(chain, extended.root, slot);
        Ok(Self {
            state,
            fork,
            proposer,
            pubkey,
            parent,
            execution,
            parent_gas_limit,
            health,
            gloas_bid,
        })
    }

    /// The slots of the last epoch's blocks on the parent's chain, and the finalized epoch.
    fn health(chain: &Chain<P>, parent: Root, slot: Slot) -> ChainHealth {
        let head = chain.head();
        let blocks = chain.store().blocks();
        let oldest = Slot(slot.0.saturating_sub(P::SLOTS_PER_EPOCH));
        let mut block_slots = BTreeSet::new();
        let mut root = parent;
        while let Some(node) = blocks.get(&root) {
            if node.slot < oldest {
                break;
            }
            block_slots.insert(node.slot);
            root = node.parent_root;
        }
        ChainHealth {
            current_slot: slot,
            block_slots,
            finalized_epoch: head.finalized.epoch,
        }
    }

    /// Gas limit of the latest payload a state records, zero before the merge.
    const fn latest_gas_limit(state: &combined::BeaconState<P>) -> u64 {
        match state {
            combined::BeaconState::Phase0(_) | combined::BeaconState::Altair(_) => 0,
            combined::BeaconState::Bellatrix(state) => {
                state.latest_execution_payload_header.gas_limit
            }
            combined::BeaconState::Capella(state) => {
                state.latest_execution_payload_header.gas_limit
            }
            combined::BeaconState::Deneb(state) => state.latest_execution_payload_header.gas_limit,
            combined::BeaconState::Electra(state) => {
                state.latest_execution_payload_header.gas_limit
            }
            combined::BeaconState::Fulu(state) => state.latest_execution_payload_header.gas_limit,
            combined::BeaconState::Gloas(state) => state.latest_execution_payload_bid.gas_limit,
            combined::BeaconState::Hstar(state) => state.latest_execution_payload_bid.gas_limit,
        }
    }
}
