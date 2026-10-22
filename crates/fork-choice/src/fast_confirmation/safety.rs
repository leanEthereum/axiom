//! LMD-GHOST safety of one block: whether its support beats every adversarial scenario.

use std::collections::HashSet;

use axiom_state_transition::EpochCommittees;
use axiom_types::{
    CommitteeIndex, Gwei, Preset, Root, ValidatorIndex, accessors::CoreState, combined::BeaconState,
};

use super::slot_range::SlotRange;
use crate::{ForkChoiceError, ForkChoiceNode, Ghost, Store, committee_weight::CommitteeWeight};

/// The store, weighed by a balance source, under the head's committee shuffling.
///
/// Every safety quantity of the fast confirmation rule reads exactly these three things.
#[derive(Clone, Copy, Debug)]
pub(super) struct Safety<'a, P: Preset> {
    /// The store.
    store: &'a Store<P>,
    /// The state whose validator set weighs the votes.
    balance_source: &'a BeaconState<P>,
    /// The head, whose chain fixes the committees.
    head: Root,
}

impl<'a, P: Preset> Safety<'a, P> {
    /// The view of a store through a balance source, under a head's shuffling.
    pub(super) const fn new(
        store: &'a Store<P>,
        balance_source: &'a BeaconState<P>,
        head: Root,
    ) -> Self {
        Self {
            store,
            balance_source,
            head,
        }
    }

    /// Whether a block is LMD-GHOST safe: its support beats the safety threshold.
    ///
    /// See `is_one_confirmed` in the phase0 fast confirmation spec.
    pub(super) fn is_one_confirmed(&self, root: Root) -> Result<bool, ForkChoiceError> {
        let support = Ghost::new(self.store, self.balance_source)
            .attestation_scores()
            .get(&root)
            .copied()
            .unwrap_or_default();
        Ok(support > self.safety_threshold(root)?)
    }

    /// Most adversarial weight in a slot range's committees, less known equivocators.
    ///
    /// Threshold: the configured byzantine percentage of the range's committee weight.
    /// See `compute_adversarial_weight` in the phase0 fast confirmation spec.
    pub(super) fn adversarial_weight_in(&self, range: SlotRange) -> Result<Gwei, ForkChoiceError> {
        let store = self.store;
        let state = self.balance_source;
        let maximum = range.committee_weight::<P>(state.total_active_balance());
        let adversarial = maximum / 100 * store.config.confirmation_byzantine_threshold;

        let epoch = state.current_epoch();
        let equivocating: Gwei = self
            .committee_members(range)?
            .into_iter()
            .filter(|index| store.votes.is_equivocating(*index))
            .filter_map(|index| state.validators().get(index.as_usize()))
            .filter(|validator| validator.is_active_at(epoch))
            .map(|validator| validator.effective_balance)
            .sum();
        Ok(adversarial.saturating_sub(equivocating))
    }

    /// The support a block needs to stay the LMD-GHOST winner.
    ///
    /// Threshold: (maximum support + proposer boost - discount) / 2 + adversarial weight.
    /// See `compute_safety_threshold` in the phase0 fast confirmation spec.
    fn safety_threshold(&self, root: Root) -> Result<Gwei, ForkChoiceError> {
        let store = self.store;
        let block = store
            .blocks
            .get(&root)
            .copied()
            .ok_or(ForkChoiceError::MissingState(root))?;
        let parent_slot = store.blocks.slot_of(&block.parent_root);

        let total = self.balance_source.total_active_balance();
        let proposer_score =
            CommitteeWeight::of(self.balance_source).percent(store.config.proposer_score_boost);
        let maximum_support =
            SlotRange::new(parent_slot + 1, store.current_slot().saturating_sub(1))
                .committee_weight::<P>(total);
        let discount = self.empty_slot_support_discount(root)?;
        let adversarial = self.adversarial_weight(root)?;

        let ceiling = maximum_support + proposer_score + adversarial * 2;
        Ok(if discount < ceiling {
            (ceiling - discount) / 2
        } else {
            Gwei::ZERO
        })
    }

    /// Most adversarial weight that can support a block, from its slot to the last one.
    fn adversarial_weight(&self, root: Root) -> Result<Gwei, ForkChoiceError> {
        let store = self.store;
        let block = store
            .blocks
            .get(&root)
            .copied()
            .ok_or(ForkChoiceError::MissingState(root))?;
        let end = store.current_slot().saturating_sub(1);
        let block_epoch = block.slot.epoch::<P>();
        // Crossing an epoch boundary starts the range at the block's epoch start.
        let parent_epoch = store.blocks.slot_of(&block.parent_root).epoch::<P>();
        let start = if block_epoch > parent_epoch {
            block_epoch.start_slot::<P>()
        } else {
            block.slot
        };
        self.adversarial_weight_in(SlotRange::new(start, end))
    }

    /// Weight of parent votes from the committees of empty slots before a block, beyond adversarial.
    ///
    /// See `compute_empty_slot_support_discount` in the phase0 fast confirmation spec.
    fn empty_slot_support_discount(&self, root: Root) -> Result<Gwei, ForkChoiceError> {
        let store = self.store;
        let block = store
            .blocks
            .get(&root)
            .copied()
            .ok_or(ForkChoiceError::MissingState(root))?;
        let parent_slot = store.blocks.slot_of(&block.parent_root);
        if parent_slot + 1 == block.slot {
            return Ok(Gwei::ZERO);
        }
        let range = SlotRange::new(parent_slot + 1, block.slot.saturating_sub(1));
        // From Gloas on, the parent node keeps the payload status the block builds on.
        let parent = store
            .blocks
            .ancestor_node(ForkChoiceNode::pending(root), parent_slot)
            .unwrap_or_else(|| ForkChoiceNode::pending(block.parent_root));
        let support = self.node_support_in(parent, range)?;
        let adversarial = self.adversarial_weight_in(range)?;
        Ok(support.saturating_sub(adversarial))
    }

    /// Stake of the committees of a slot range whose vote supports exactly a node.
    ///
    /// See `get_node_support_between_slots` in the phase0 fast confirmation spec.
    fn node_support_in(
        &self,
        node: ForkChoiceNode,
        range: SlotRange,
    ) -> Result<Gwei, ForkChoiceError> {
        let state = self.balance_source;
        let epoch = state.current_epoch();
        let support = self
            .committee_members(range)?
            .into_iter()
            .filter_map(|index| {
                let validator = state.validators().get(index.as_usize())?;
                let votes_for_node = self
                    .store
                    .votes
                    .counted(index)
                    .and_then(|message| self.store.blocks.supported_node(message))
                    .is_some_and(|supported| supported == node);
                (!validator.slashed && validator.is_active_at(epoch) && votes_for_node)
                    .then_some(validator.effective_balance)
            })
            .sum();
        Ok(support)
    }

    /// Members of every committee in a slot range, by the head's shuffling.
    ///
    /// See `get_slot_committee` in the phase0 fast confirmation spec.
    fn committee_members(
        &self,
        range: SlotRange,
    ) -> Result<HashSet<ValidatorIndex>, ForkChoiceError> {
        let mut members = HashSet::new();
        if range.is_empty() {
            return Ok(members);
        }
        let head = self.head;
        let state = self
            .store
            .block_states
            .get(&head)
            .ok_or(ForkChoiceError::MissingState(head))?;
        let mut cached: Option<EpochCommittees> = None;
        for slot in range.slots() {
            let epoch = slot.epoch::<P>();
            if cached
                .as_ref()
                .is_none_or(|committees| committees.epoch() != epoch)
            {
                cached = Some(EpochCommittees::compute(state.beacon(), epoch));
            }
            let committees = cached.as_ref().ok_or(ForkChoiceError::MissingState(head))?;
            for index in 0..committees.committees_per_slot() {
                if let Some(committee) = committees.committee(slot, CommitteeIndex(index)) {
                    members.extend(committee.iter().copied());
                }
            }
        }
        Ok(members)
    }
}
