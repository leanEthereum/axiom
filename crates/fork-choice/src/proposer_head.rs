//! The proposer's choice of parent: building on the head, or reorging a late, weak one.

use std::{collections::HashMap, sync::Arc};

use axiom_state_transition::EpochCommittees;
use axiom_types::{CommitteeIndex, Gwei, Preset, Root, Slot, accessors::CoreState};

use crate::{BlockNode, Ghost};

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
/// - its FFG information matches its parent's,
/// - finality is recent,
/// - the proposer is on time,
/// - the reorg spans one slot,
/// - the head is weak and its parent strong.
///
/// A head that equivocated in the previous slot is reorged more eagerly.
///
/// See `get_proposer_head` in the Fulu fork choice spec.
#[derive(Debug)]
pub(crate) struct LateHeadReorg<'a, P: Preset> {
    /// The store, seen through its justified state.
    ghost: Ghost<'a, P>,
    /// The head's root.
    head: Root,
    /// The head's block.
    head_block: BlockNode,
    /// The head's parent block.
    parent_block: BlockNode,
    /// The committees of the head's epoch, by the head's shuffling.
    head_committees: Arc<EpochCommittees>,
}

impl<'a, P: Preset> LateHeadReorg<'a, P> {
    /// The decision for a head, its parent, and the committees of the head's epoch.
    pub(crate) const fn new(
        ghost: Ghost<'a, P>,
        head: Root,
        head_block: BlockNode,
        parent_block: BlockNode,
        head_committees: Arc<EpochCommittees>,
    ) -> Self {
        Self {
            ghost,
            head,
            head_block,
            parent_block,
            head_committees,
        }
    }

    /// The block a proposer at a slot should build on.
    pub(crate) fn parent_for(&self, slot: Slot) -> Root {
        let store = self.ghost.store();
        let head = self.head;
        let parent_root = self.head_block.parent_root;
        let config = store.config();

        let head_late = !store.block_timeliness.get(&head).copied().unwrap_or(false);
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

        // Both thresholds weigh the same votes, so the scores are computed once.
        let scores = self.ghost.attestation_scores();
        let head_weak = self.is_head_weak(&scores);
        let parent_strong = self.is_parent_strong(&scores, parent_root);
        let proposer_equivocation = store.blocks.has_proposer_equivocation(head);

        let reorg = head_late
            && ffg_competitive
            && finalization_ok
            && proposing_on_time
            && single_slot_reorg
            && head_weak
            && parent_strong;
        if reorg || (head_weak && current_time_ok && proposer_equivocation) {
            parent_root
        } else {
            head
        }
    }

    /// Whether the head's support is below the reorg threshold.
    ///
    /// Equivocators in the head slot's committees count toward the head.
    /// More votes can then only make the head stronger, which keeps the rule monotonic.
    ///
    /// See `is_head_weak` in the phase0 fork choice spec.
    fn is_head_weak(&self, scores: &HashMap<Root, Gwei>) -> bool {
        let store = self.ghost.store();
        let balance_source = self.ghost.balance_source();
        let threshold = self
            .ghost
            .committee_fraction(store.config().reorg_head_weight_threshold);

        let mut weight = scores.get(&self.head).copied().unwrap_or_default();
        let head_slot = self.head_block.slot;
        let committees = &self.head_committees;
        for index in 0..committees.committees_per_slot() {
            let committee = committees
                .committee(head_slot, CommitteeIndex(index))
                .unwrap_or(&[]);
            let equivocating: Gwei = committee
                .iter()
                .filter(|validator| store.votes.is_equivocating(**validator))
                .map(|validator| {
                    balance_source.validators()[validator.as_usize()].effective_balance
                })
                .sum();
            weight += equivocating;
        }
        weight < threshold
    }

    /// Whether the parent's support is above the reorg threshold.
    fn is_parent_strong(&self, scores: &HashMap<Root, Gwei>, parent: Root) -> bool {
        let threshold = self
            .ghost
            .committee_fraction(self.ghost.store().config().reorg_parent_weight_threshold);
        scores.get(&parent).copied().unwrap_or_default() > threshold
    }
}
