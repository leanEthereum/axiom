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
        let current_time_ok = self.head_block.slot + 1 == slot;
        let single_slot_reorg = self.parent_slot_ok() && current_time_ok;
        let head_weak = self.head_weak();
        let proposer_equivocation = self
            .ghost
            .store()
            .blocks
            .has_proposer_equivocation(self.head.root);

        let reorg = self.head_late()
            && self.shuffling_stable(slot)
            && self.ffg_competitive()
            && self.finalization_ok(slot)
            && self.proposing_on_time()
            && single_slot_reorg
            && head_weak
            && self.parent_strong();
        if reorg || (head_weak && current_time_ok && proposer_equivocation) {
            self.parent
        } else {
            self.head
        }
    }

    /// Whether the engine should follow the parent rather than the head, at a slot.
    ///
    /// It mirrors the reorg rule for the slot after the head, with two differences:
    ///
    /// - during the head's own slot, the weights are not checked,
    /// - in the next slot, the proposer must still be on time.
    ///
    /// The head's slot is too early for weights: its votes only count from the next slot on.
    /// See `should_override_forkchoice_update` in the Bellatrix fork choice spec of v1.4.0.
    pub(crate) fn overrides_update(&self, current_slot: Slot) -> bool {
        let proposal_slot = self.head_block.slot + 1;
        let current_time_ok = self.head_block.slot == current_slot
            || (proposal_slot == current_slot && self.proposing_on_time());
        // Votes of the head's slot are not applied yet, so weak and strong cannot be told.
        let weights_ok =
            current_slot <= self.head_block.slot || (self.head_weak() && self.parent_strong());
        self.head_late()
            && self.shuffling_stable(proposal_slot)
            && self.ffg_competitive()
            && self.finalization_ok(proposal_slot)
            && self.parent_slot_ok()
            && current_time_ok
            && weights_ok
    }

    /// Whether the head arrived after the attestation deadline of its slot.
    ///
    /// See `is_head_late` in the phase0 fork choice spec.
    fn head_late(&self) -> bool {
        !self
            .ghost
            .store()
            .block_timeliness
            .get(&self.head.root)
            .is_some_and(|timeliness| timeliness.attestation)
    }

    /// Whether a proposal at the slot keeps its proposer, whichever parent it builds on.
    ///
    /// Before Fulu, a reorg at an epoch boundary could change the slot's proposer.
    /// See `is_shuffling_stable` in the phase0 fork choice spec.
    const fn shuffling_stable(&self, slot: Slot) -> bool {
        !self.boundary_sensitive || !slot.is_epoch_start::<P>()
    }

    /// Whether the parent would realize the same justification as the head.
    ///
    /// See `is_ffg_competitive` in the phase0 fork choice spec.
    fn ffg_competitive(&self) -> bool {
        let justifications = &self.ghost.store().unrealized_justifications;
        justifications.get(&self.head.root) == justifications.get(&self.parent.root)
    }

    /// Whether the chain finalized recently enough, seen from the slot.
    ///
    /// See `is_finalization_ok` in the phase0 fork choice spec.
    fn finalization_ok(&self, slot: Slot) -> bool {
        let store = self.ghost.store();
        slot.epoch::<P>() - store.finalized_checkpoint().epoch
            <= store.config().reorg_max_epochs_since_finalization
    }

    /// Whether the store's clock is still before the reorg cutoff of its slot.
    ///
    /// See `is_proposing_on_time` in the phase0 fork choice spec.
    const fn proposing_on_time(&self) -> bool {
        let store = self.ghost.store();
        let clock = store.slot_clock();
        clock.time_into_slot_ms(store.time_ms())
            <= clock.component_ms(store.config().proposer_reorg_cutoff_bps)
    }

    /// Whether the head directly follows its parent's slot, so a reorg spans one slot.
    fn parent_slot_ok(&self) -> bool {
        self.parent_block.slot + 1 == self.head_block.slot
    }

    /// Whether the head drew too few votes to resist the next proposer's boost.
    ///
    /// See `is_head_weak` in the phase0 fork choice spec.
    fn head_weak(&self) -> bool {
        let threshold = self
            .committee
            .percent(self.ghost.store().config().reorg_head_weight_threshold);
        self.ghost.is_weak(
            self.head_score,
            threshold,
            self.head_block.slot,
            self.head_committees,
        )
    }

    /// Whether the parent drew enough votes that the head's missing votes are not being withheld.
    ///
    /// Threshold: strictly above the parent threshold, whatever the parent's payload status.
    /// See `is_parent_strong` in the phase0 and Gloas fork choice specs.
    fn parent_strong(&self) -> bool {
        self.parent_score
            > self
                .committee
                .percent(self.ghost.store().config().reorg_parent_weight_threshold)
    }
}
