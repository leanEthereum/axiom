//! The proposer's choice of parent: building on the head, or reorging a late, weak one.

use axiom_types::{CommitteeIndex, Gwei, Preset, Root, Slot};

use crate::{ForkChoiceError, Store};

impl<P: Preset> Store<P> {
    /// The block a proposer at a slot should build on.
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
    ///
    /// # Errors
    ///
    /// Fails when the head still holds the proposer boost, or its state is missing.
    pub fn proposer_head(&mut self, head: Root, slot: Slot) -> Result<Root, ForkChoiceError> {
        if self.proposer_boost_root == head {
            return Err(ForkChoiceError::HeadStillBoosted);
        }
        let head_block = *self
            .blocks
            .get(&head)
            .ok_or(ForkChoiceError::MissingState(head))?;
        let parent_root = head_block.parent_root;
        let parent_block = *self
            .blocks
            .get(&parent_root)
            .ok_or(ForkChoiceError::MissingState(parent_root))?;

        let head_late = !self.block_timeliness.get(&head).copied().unwrap_or(false);
        let ffg_competitive = self.unrealized_justifications.get(&head)
            == self.unrealized_justifications.get(&parent_root);
        let finalization_ok = slot.epoch::<P>() - self.finalized_checkpoint.epoch
            <= self.config.reorg_max_epochs_since_finalization;
        let proposing_on_time = self.time_into_slot_ms()
            <= self.slot_component_ms(self.config.proposer_reorg_cutoff_bps);
        let parent_slot_ok = parent_block.slot + 1 == head_block.slot;
        let current_time_ok = head_block.slot + 1 == slot;
        let single_slot_reorg = parent_slot_ok && current_time_ok;
        let head_weak = self.is_head_weak(head)?;
        let parent_strong = self.is_parent_strong(parent_root)?;
        let proposer_equivocation = self.is_proposer_equivocation(head);

        let reorg = head_late
            && ffg_competitive
            && finalization_ok
            && proposing_on_time
            && single_slot_reorg
            && head_weak
            && parent_strong;
        if reorg || (head_weak && current_time_ok && proposer_equivocation) {
            Ok(parent_root)
        } else {
            Ok(head)
        }
    }

    /// Whether the head's support is below the reorg threshold.
    ///
    /// Equivocators in the head slot's committees count toward the head.
    /// More votes can then only make the head stronger, which keeps the rule monotonic.
    ///
    /// See `is_head_weak` in the phase0 fork choice spec.
    fn is_head_weak(&mut self, head: Root) -> Result<bool, ForkChoiceError> {
        let justified = self.justified_checkpoint;
        let justified_state = self.checkpoint_state(justified)?.beacon().clone();
        let threshold =
            Self::committee_fraction(&justified_state, self.config.reorg_head_weight_threshold);

        let mut weight = self
            .attestation_scores(&justified_state)
            .get(&head)
            .copied()
            .unwrap_or_default();

        let head_slot = self
            .blocks
            .get(&head)
            .map_or(Slot::GENESIS, |node| node.slot);
        let head_state = self
            .block_states
            .get_mut(&head)
            .ok_or(ForkChoiceError::MissingState(head))?;
        let committees = head_state.committees(head_slot.epoch::<P>())?;
        for index in 0..committees.committees_per_slot() {
            let committee = committees
                .committee(head_slot, CommitteeIndex(index))
                .unwrap_or(&[]);
            let equivocating: Gwei = committee
                .iter()
                .filter(|validator| self.votes.is_equivocating(**validator))
                .map(|validator| justified_state.validators[validator.as_usize()].effective_balance)
                .sum();
            weight += equivocating;
        }
        Ok(weight < threshold)
    }

    /// Whether the parent's support is above the reorg threshold.
    fn is_parent_strong(&mut self, parent: Root) -> Result<bool, ForkChoiceError> {
        let justified = self.justified_checkpoint;
        let justified_state = self.checkpoint_state(justified)?.beacon().clone();
        let threshold =
            Self::committee_fraction(&justified_state, self.config.reorg_parent_weight_threshold);
        let weight = self
            .attestation_scores(&justified_state)
            .get(&parent)
            .copied()
            .unwrap_or_default();
        Ok(weight > threshold)
    }

    /// Whether the head's proposer signed another block for the same slot.
    fn is_proposer_equivocation(&self, head: Root) -> bool {
        let Some(block) = self.blocks.get(&head) else {
            return false;
        };
        self.blocks
            .iter()
            .filter(|(_, other)| {
                other.proposer_index == block.proposer_index && other.slot == block.slot
            })
            .count()
            > 1
    }
}
