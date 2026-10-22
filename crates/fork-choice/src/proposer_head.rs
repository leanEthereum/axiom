//! The proposer's choice of parent: building on the head, or reorging a late, weak one.

use axiom_state_transition::EpochCommittees;
use axiom_types::{Gwei, Preset, Slot};

use crate::{BlockNode, ForkChoiceNode, Ghost, committee_weight::CommitteeWeight};

/// A late head and its parent, weighed by a proposer deciding which one to build on.
///
/// # Overview
///
/// A head that arrived late and drew few votes can be orphaned by the next proposer.
/// The next proposer builds on the head's parent, and its boost outweighs the late block.
/// That punishes late publication without risking a deep reorg.
///
/// Every condition must hold for that reorg:
///
/// - the head was late,
/// - before Fulu, the proposal is not at an epoch boundary,
/// - the head's FFG information matches its parent's,
/// - finality is recent,
/// - the proposer is on time,
/// - the reorg spans one slot,
/// - the head is weak and its parent strong.
///
/// A head that equivocated in the previous slot is reorged more eagerly.
///
/// By default the head drew under 20% of a committee, and its parent over 160%.
/// Honest attesters that voted on time therefore already sit on the parent.
/// So an adversary cannot use the rule to undo a block the honest majority saw in time.
///
/// The single-slot and finality bounds keep a buggy or attacked proposer from long reorgs.
///
/// See `get_proposer_head` in the phase0, Fulu, and Gloas fork choice specs.
#[derive(Debug)]
pub(crate) struct LateHeadReorg<'a, P: Preset> {
    /// The store, seen through its justified state.
    pub(crate) ghost: Ghost<'a, P>,
    /// The head node.
    pub(crate) head: ForkChoiceNode,
    /// The head's block.
    pub(crate) head_block: BlockNode,
    /// The parent node the head builds on.
    pub(crate) parent: ForkChoiceNode,
    /// The head's parent block.
    pub(crate) parent_block: BlockNode,
    /// The committees of the head's epoch, by the head's shuffling.
    pub(crate) head_committees: &'a EpochCommittees,
    /// Whether a reorg at an epoch boundary could change the proposer, as before Fulu.
    pub(crate) boundary_sensitive: bool,
    /// Attestation score of the head block.
    pub(crate) head_score: Gwei,
    /// Attestation score of the parent block.
    pub(crate) parent_score: Gwei,
    /// One slot's committee weight in the justified state, the unit of both thresholds.
    pub(crate) committee: CommitteeWeight,
}

impl<P: Preset> LateHeadReorg<'_, P> {
    /// The node a proposer at a slot should build on.
    pub(crate) fn parent_for(&self, slot: Slot) -> ForkChoiceNode {
        let store = self.ghost.store();
        let head = self.head.root;
        let parent_root = self.parent.root;
        let config = store.config();

        let head_late = !store
            .block_timeliness
            .get(&head)
            .is_some_and(|timeliness| timeliness.attestation);
        // Before Fulu, a reorg at an epoch boundary could change the slot's proposer.
        let shuffling_stable = !self.boundary_sensitive || !slot.is_epoch_start::<P>();
        let ffg_competitive = store.unrealized_justifications.get(&head)
            == store.unrealized_justifications.get(&parent_root);
        let finalization_ok = slot.epoch::<P>() - store.finalized_checkpoint().epoch
            <= config.reorg_max_epochs_since_finalization;
        let clock = store.slot_clock();
        let proposing_on_time = clock.time_into_slot_ms(store.time_ms())
            <= clock.component_ms(config.proposer_reorg_cutoff_bps);
        let parent_slot_ok = self.parent_block.slot + 1 == self.head_block.slot;
        let current_time_ok = self.head_block.slot + 1 == slot;
        let single_slot_reorg = parent_slot_ok && current_time_ok;

        let head_weak = self.ghost.is_weak(
            self.head_score,
            self.committee.percent(config.reorg_head_weight_threshold),
            self.head_block.slot,
            self.head_committees,
        );
        // Threshold: strictly above the parent threshold, whatever the parent's payload status.
        // See `is_parent_strong` in the phase0 and Gloas fork choice specs.
        let parent_strong =
            self.parent_score > self.committee.percent(config.reorg_parent_weight_threshold);
        let proposer_equivocation = store.blocks.has_proposer_equivocation(head);

        let reorg = head_late
            && shuffling_stable
            && ffg_competitive
            && finalization_ok
            && proposing_on_time
            && single_slot_reorg
            && head_weak
            && parent_strong;
        if reorg || (head_weak && current_time_ok && proposer_equivocation) {
            self.parent
        } else {
            self.head
        }
    }
}
