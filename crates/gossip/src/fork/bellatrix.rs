//! The Bellatrix gossip rules: blocks carry an execution payload once the merge happened.
//!
//! See the Bellatrix p2p spec.

use axiom_fork_choice::ExecutionStatus;
use axiom_state_transition::State;
use axiom_types::{
    BlsSignature, ChainConfig, Hash32, Preset, Root, Slot,
    accessors::CoreState,
    bellatrix::{
        Attestation, AttesterSlashing, BeaconBlock, BeaconState, ExecutionPayload,
        SignedAggregateAndProof, SignedBeaconBlock,
    },
    combined,
};

use super::{GossipFork, Verdict, VoteIndex, VoteWindow};
use crate::{ChainView, Detail, GossipError};

impl<P: Preset> GossipFork for BeaconState<P> {
    type SignedBeaconBlock = SignedBeaconBlock<P>;
    type SignedAggregateAndProof = SignedAggregateAndProof<P>;
    type SubnetAttestation = Attestation<P>;
    type AttesterSlashing = AttesterSlashing<P>;

    const VOTE_WINDOW: VoteWindow = VoteWindow::SlotRange;
    const VOTE_INDEX: VoteIndex = VoteIndex::Committee;

    fn into_any_block(signed: SignedBeaconBlock<P>) -> combined::SignedBeaconBlock<P> {
        combined::SignedBeaconBlock::Bellatrix(signed)
    }

    fn split_block(signed: &SignedBeaconBlock<P>) -> (&BeaconBlock<P>, &BlsSignature) {
        (&signed.message, &signed.signature)
    }

    fn execution_block_hash(block: &BeaconBlock<P>) -> Hash32 {
        block.body.execution_payload.block_hash
    }

    fn failed_parent(view: &ChainView<'_, P>, block: &BeaconBlock<P>) -> GossipError {
        // The parent has no post-state, so the justified state, always imported, stands in.
        // Merge completion never reverts, so the justified state answers for the parent too.
        let justified = view.store.justified_checkpoint().root;
        let enabled = view
            .store
            .block_state(&justified)
            .is_none_or(|state| MergeBlock(block).is_execution_enabled(state));
        if enabled {
            ParentPayload::of(view, block.parent_root).failed()
        } else {
            GossipError::reject("block's parent is invalid and execution is not enabled")
                .with(Detail::Block(block.parent_root))
        }
    }

    fn check_execution(
        view: &ChainView<'_, P>,
        head: &State<P>,
        block: &BeaconBlock<P>,
    ) -> Verdict {
        if !MergeBlock(block).is_execution_enabled(head) {
            return Ok(());
        }
        PayloadTimestamp::new(block.body.execution_payload.timestamp, block.slot)
            .check(view.config(), head)?;
        ParentPayload::of(view, block.parent_root).not_invalid()
    }
}

/// A Bellatrix block, whose payload may be empty before the merge.
#[derive(Clone, Copy, Debug)]
struct MergeBlock<'a, P: Preset>(&'a BeaconBlock<P>);

impl<P: Preset> MergeBlock<'_, P> {
    /// Whether the block's payload counts: the merge happened, or this block makes it happen.
    ///
    /// The state may be of an earlier fork, when the head has not crossed into Bellatrix yet.
    /// Such a state has not merged.
    /// See `is_execution_enabled` in the Bellatrix beacon chain spec.
    fn is_execution_enabled(self, state: &State<P>) -> bool {
        state.beacon().is_merge_transition_complete()
            || self.0.body.execution_payload != ExecutionPayload::default()
    }
}

/// What the execution engine said about a block's parent payload.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ParentPayload {
    /// The parent block.
    root: Root,
    /// The engine's verdict, unknown when the payload is not validated yet.
    status: Option<ExecutionStatus>,
}

impl ParentPayload {
    /// The verdict a view records for a parent block's payload.
    pub(crate) fn of<P: Preset>(view: &ChainView<'_, P>, root: Root) -> Self {
        Self {
            root,
            status: view.payload_status(&root),
        }
    }

    /// The verdict on a block whose parent failed to import.
    ///
    /// A parent with an unvalidated payload failed for consensus reasons, so its child is invalid.
    /// A parent whose payload the engine processed may have failed for that payload alone.
    pub(crate) fn failed(self) -> GossipError {
        let verdict = if self
            .status
            .is_none_or(|status| status == ExecutionStatus::Optimistic)
        {
            GossipError::reject("block's parent is invalid and its payload is optimistic")
        } else {
            GossipError::ignore("block's parent is invalid and its payload is processed")
        };
        verdict.with(Detail::Block(self.root))
    }

    /// Ignores a block whose imported parent carries a payload the engine found invalid.
    pub(crate) fn not_invalid(self) -> Verdict {
        if self.status == Some(ExecutionStatus::Invalid) {
            return Err(
                GossipError::ignore("block's parent is valid and its payload is invalid")
                    .with(Detail::Block(self.root)),
            );
        }
        Ok(())
    }
}

/// A payload's timestamp, which must be the start of its block's slot.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PayloadTimestamp {
    /// The payload's timestamp, in seconds.
    timestamp: u64,
    /// The block's slot.
    slot: Slot,
}

impl PayloadTimestamp {
    /// A timestamp claimed for a slot.
    pub(crate) const fn new(timestamp: u64, slot: Slot) -> Self {
        Self { timestamp, slot }
    }

    /// Rejects a timestamp other than the slot's start.
    ///
    /// See `compute_time_at_slot` in the Bellatrix beacon chain spec.
    pub(crate) fn check<P: Preset>(self, config: &ChainConfig, state: &State<P>) -> Verdict {
        let expected = state.beacon().genesis_time() + self.slot.0 * config.slot_duration_ms / 1000;
        if self.timestamp != expected {
            return Err(
                GossipError::reject("incorrect execution payload timestamp").with(
                    Detail::Mismatch {
                        actual: self.timestamp,
                        expected,
                    },
                ),
            );
        }
        Ok(())
    }
}
