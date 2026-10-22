//! The fast confirmation rule: blocks that stay canonical under synchrony, long before finality.

use std::collections::HashSet;

use axiom_state_transition::{EpochCommittees, State};
use axiom_types::{
    BeaconState, Checkpoint, CommitteeIndex, Epoch, Gwei, Hash32, Preset, Root, Slot,
    ValidatorIndex,
};

use crate::{ForkChoiceError, Store};

/// Per mille added to a committee weight estimate across an epoch boundary.
///
/// It keeps the rule safe with high probability when the range covers no full epoch.
/// See the fast confirmation spec's constants.
const COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR: u64 = 5;

/// What the fast confirmation rule tracks between slots.
///
/// # Overview
///
/// A block is confirmed when two things hold, assuming synchrony and at most 25% byzantine stake.
///
/// - Every block of its chain has enough votes to win LMD-GHOST against any conflict.
/// - No conflicting checkpoint can be justified in this epoch or the next.
///
/// A confirmed block then stays canonical for every honest node.
/// See D'Amato et al., "Fast Confirmation Rule for the Ethereum Consensus Protocol", 2024,
/// and the phase0 `fast-confirmation.md` spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastConfirmation {
    /// Most recently confirmed block.
    pub confirmed_root: Root,
    /// Justified checkpoint every honest node saw at the start of the previous epoch.
    pub previous_epoch_observed_justified_checkpoint: Checkpoint,
    /// Justified checkpoint every honest node saw at the start of the current epoch.
    pub current_epoch_observed_justified_checkpoint: Checkpoint,
    /// Greatest unrealized justification at the last slot of the previous epoch.
    pub previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    /// Head at the start of the previous slot.
    pub previous_slot_head: Root,
    /// Head at the start of the current slot.
    pub current_slot_head: Root,
}

impl FastConfirmation {
    /// Tracking that starts conservatively at the store's finalized checkpoint.
    ///
    /// See `get_fast_confirmation_store` in the phase0 fast confirmation spec.
    #[must_use]
    pub const fn new<P: Preset>(store: &Store<P>) -> Self {
        let finalized = store.finalized_checkpoint();
        Self {
            confirmed_root: finalized.root,
            previous_epoch_observed_justified_checkpoint: finalized,
            current_epoch_observed_justified_checkpoint: finalized,
            previous_epoch_greatest_unrealized_checkpoint: finalized,
            previous_slot_head: finalized.root,
            current_slot_head: finalized.root,
        }
    }

    /// Runs once per slot, after the previous slots' votes reached the store.
    ///
    /// See `on_fast_confirmation` in the phase0 fast confirmation spec.
    ///
    /// # Errors
    ///
    /// Fails when a state the rule reads is missing from the store.
    pub fn on_fast_confirmation<P: Preset>(
        &mut self,
        store: &mut Store<P>,
    ) -> Result<(), ForkChoiceError> {
        self.update_variables(store)?;
        self.confirmed_root = self.latest_confirmed(store)?;
        Ok(())
    }

    /// Execution block hash of the confirmed block, the engine's safe head.
    ///
    /// See `get_safe_execution_block_hash` in the Bellatrix fast confirmation spec.
    #[must_use]
    pub fn safe_execution_block_hash<P: Preset>(&self, store: &Store<P>) -> Hash32 {
        store
            .blocks()
            .get(&self.confirmed_root)
            .map_or(Hash32::ZERO, |node| node.execution_block_hash)
    }

    /// Rotates the slot heads and the observed checkpoints.
    ///
    /// See `update_fast_confirmation_variables` in the phase0 fast confirmation spec.
    fn update_variables<P: Preset>(&mut self, store: &mut Store<P>) -> Result<(), ForkChoiceError> {
        self.previous_slot_head = self.current_slot_head;
        self.current_slot_head = store.head()?;
        let slot = store.current_slot();
        if (slot + 1).is_epoch_start::<P>() {
            self.previous_epoch_greatest_unrealized_checkpoint =
                store.unrealized_justified_checkpoint;
        }
        if slot.is_epoch_start::<P>() {
            self.previous_epoch_observed_justified_checkpoint =
                self.current_epoch_observed_justified_checkpoint;
            self.current_epoch_observed_justified_checkpoint =
                self.previous_epoch_greatest_unrealized_checkpoint;
        }
        Ok(())
    }

    /// The most recent confirmed block.
    ///
    /// # Algorithm
    ///
    /// - Phase 1 falls back to finality when the confirmed block is stale, off the canonical
    ///   chain, or fails reconfirmation at an epoch start.
    /// - Phase 2 restarts from the observed justified checkpoint when it is fresher.
    /// - Phase 3 walks forward along the canonical chain, confirming while the checks hold.
    ///
    /// See `get_latest_confirmed` in the phase0 fast confirmation spec.
    fn latest_confirmed<P: Preset>(&self, store: &mut Store<P>) -> Result<Root, ForkChoiceError> {
        let mut confirmed = self.confirmed_root;
        let current_epoch = store.current_epoch();
        // The store does not change during the rule, so the head recorded this slot stays current.
        let head = self.current_slot_head;
        let is_epoch_start = store.current_slot().is_epoch_start::<P>();

        // Phase 1: fall back to finality.
        let stale = Self::block_epoch(store, confirmed) + 1 < current_epoch;
        let off_chain = !store.blocks.is_ancestor(head, confirmed);
        if stale
            || off_chain
            || (is_epoch_start && !self.is_confirmed_chain_safe(store, confirmed)?)
        {
            confirmed = store.finalized_checkpoint.root;
        }

        // Phase 2: restart from the observed justified checkpoint.
        let observed = self.current_epoch_observed_justified_checkpoint;
        let observed_slot = Self::block_slot(store, observed.root);
        let restart = is_epoch_start
            && observed_slot.epoch::<P>() + 1 == current_epoch
            && store.unrealized_justifications.get(&head) == Some(&observed)
            && Self::block_slot(store, confirmed) < observed_slot;
        if restart {
            confirmed = observed.root;
        }

        // Phase 3: advance.
        if Self::block_epoch(store, confirmed) + 1 >= current_epoch {
            self.latest_confirmed_descendant(store, confirmed)
        } else {
            Ok(confirmed)
        }
    }

    /// The most recent confirmed block on the canonical chain after a confirmed one.
    ///
    /// See `find_latest_confirmed_descendant` in the phase0 fast confirmation spec.
    fn latest_confirmed_descendant<P: Preset>(
        &self,
        store: &mut Store<P>,
        latest_confirmed: Root,
    ) -> Result<Root, ForkChoiceError> {
        let head = self.current_slot_head;
        let current_epoch = store.current_epoch();
        let is_epoch_start = store.current_slot().is_epoch_start::<P>();
        let mut confirmed = latest_confirmed;
        let balance_source =
            Self::balance_source(store, self.current_epoch_observed_justified_checkpoint)?;
        let unrealized = |root: Root, store: &Store<P>| {
            store
                .unrealized_justifications
                .get(&root)
                .map_or(Epoch::GENESIS, |checkpoint| checkpoint.epoch)
        };

        // Phase 1: confirm blocks of the previous epoch.
        let previous_head_source = store
            .voting_source(self.previous_slot_head)
            .map_or(Epoch::GENESIS, |source| source.epoch);
        if Self::block_epoch(store, confirmed) + 1 == current_epoch
            && previous_head_source + 2 >= current_epoch
            && (is_epoch_start
                || (Self::will_no_conflicting_checkpoint_be_justified(store, head)?
                    && (unrealized(self.previous_slot_head, store) + 1 >= current_epoch
                        || unrealized(head, store) + 1 >= current_epoch)))
        {
            for root in Self::ancestor_roots(store, head, confirmed) {
                if Self::block_epoch(store, root) == current_epoch
                    || !store.blocks.is_ancestor(self.previous_slot_head, root)
                    || !Self::is_one_confirmed(store, &balance_source, root, head)?
                {
                    break;
                }
                confirmed = root;
            }
        }

        // Phase 2: confirm blocks of the current epoch, which needs its target justified.
        if is_epoch_start || unrealized(head, store) + 1 >= current_epoch {
            let mut tentative = confirmed;
            for root in Self::ancestor_roots(store, head, confirmed) {
                if Self::block_epoch(store, root) > Self::block_epoch(store, tentative)
                    && !Self::will_current_target_be_justified(store, head)?
                {
                    break;
                }
                if !Self::is_one_confirmed(store, &balance_source, root, head)? {
                    break;
                }
                tentative = root;
            }

            // Confirm only what cannot be filtered out in this epoch or the next.
            let tentative_source = store
                .voting_source(tentative)
                .map_or(Epoch::GENESIS, |source| source.epoch);
            if Self::block_epoch(store, tentative) == current_epoch
                || (tentative_source + 2 >= current_epoch
                    && (is_epoch_start
                        || Self::will_no_conflicting_checkpoint_be_justified(store, head)?))
            {
                confirmed = tentative;
            }
        }
        Ok(confirmed)
    }

    /// Whether every block of the confirmed chain after the observed checkpoint stays safe.
    ///
    /// Running it at each epoch start lets synchrony start one slot ago, not at the first run.
    /// See `is_confirmed_chain_safe` in the phase0 fast confirmation spec.
    fn is_confirmed_chain_safe<P: Preset>(
        &self,
        store: &mut Store<P>,
        confirmed: Root,
    ) -> Result<bool, ForkChoiceError> {
        let observed = self.current_epoch_observed_justified_checkpoint;
        if store.checkpoint_block(confirmed, observed.epoch) != Some(observed.root) {
            return Ok(false);
        }
        let current_epoch = store.current_epoch();
        let start_exclusive = if observed.epoch + 1 >= current_epoch {
            observed.root
        } else {
            let previous_epoch_start = (current_epoch - 1).start_slot::<P>();
            let ancestor = store
                .blocks
                .ancestor(confirmed, previous_epoch_start)
                .unwrap_or(confirmed);
            if Self::block_epoch(store, ancestor) + 1 == current_epoch {
                store
                    .blocks
                    .get(&ancestor)
                    .map_or(ancestor, |node| node.parent_root)
            } else {
                ancestor
            }
        };

        let balance_source =
            Self::balance_source(store, self.previous_epoch_observed_justified_checkpoint)?;
        for root in Self::ancestor_roots(store, confirmed, start_exclusive) {
            if !Self::is_one_confirmed(store, &balance_source, root, self.current_slot_head)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether a block is LMD-GHOST safe: its support beats the safety threshold.
    ///
    /// See `is_one_confirmed` in the phase0 fast confirmation spec.
    fn is_one_confirmed<P: Preset>(
        store: &Store<P>,
        balance_source: &BeaconState<P>,
        root: Root,
        head: Root,
    ) -> Result<bool, ForkChoiceError> {
        let support = store
            .attestation_scores(balance_source)
            .get(&root)
            .copied()
            .unwrap_or_default();
        Ok(support > Self::safety_threshold(store, balance_source, root, head)?)
    }

    /// The support a block needs to stay the LMD-GHOST winner.
    ///
    /// Threshold: (maximum support + proposer boost - discount) / 2 + adversarial weight.
    /// See `compute_safety_threshold` in the phase0 fast confirmation spec.
    fn safety_threshold<P: Preset>(
        store: &Store<P>,
        balance_source: &BeaconState<P>,
        root: Root,
        head: Root,
    ) -> Result<Gwei, ForkChoiceError> {
        let current_slot = store.current_slot();
        let block = store
            .blocks
            .get(&root)
            .copied()
            .ok_or(ForkChoiceError::MissingState(root))?;
        let parent_slot = Self::block_slot(store, block.parent_root);

        let total = balance_source.total_active_balance();
        let proposer_score =
            Store::committee_fraction(balance_source, store.config.proposer_score_boost);
        let maximum_support = Self::estimate_committee_weight::<P>(
            total,
            parent_slot + 1,
            current_slot.saturating_sub(1),
        );
        let discount = Self::empty_slot_support_discount(store, balance_source, root, head)?;
        let adversarial = Self::adversarial_weight(store, balance_source, root, head)?;

        let ceiling = maximum_support + proposer_score + adversarial * 2;
        Ok(if discount < ceiling {
            (ceiling - discount) / 2
        } else {
            Gwei::ZERO
        })
    }

    /// Most adversarial weight that can support a block, from its slot to the last one.
    fn adversarial_weight<P: Preset>(
        store: &Store<P>,
        balance_source: &BeaconState<P>,
        root: Root,
        head: Root,
    ) -> Result<Gwei, ForkChoiceError> {
        let block = store
            .blocks
            .get(&root)
            .copied()
            .ok_or(ForkChoiceError::MissingState(root))?;
        let end = store.current_slot().saturating_sub(1);
        let block_epoch = block.slot.epoch::<P>();
        // Crossing an epoch boundary starts the range at the block's epoch start.
        let start = if block_epoch > Self::block_epoch(store, block.parent_root) {
            block_epoch.start_slot::<P>()
        } else {
            block.slot
        };
        Self::compute_adversarial_weight(store, balance_source, start, end, head)
    }

    /// Weight of parent votes from the committees of empty slots before a block, beyond adversarial.
    ///
    /// See `compute_empty_slot_support_discount` in the phase0 fast confirmation spec.
    fn empty_slot_support_discount<P: Preset>(
        store: &Store<P>,
        balance_source: &BeaconState<P>,
        root: Root,
        head: Root,
    ) -> Result<Gwei, ForkChoiceError> {
        let block = store
            .blocks
            .get(&root)
            .copied()
            .ok_or(ForkChoiceError::MissingState(root))?;
        let parent_slot = Self::block_slot(store, block.parent_root);
        if parent_slot + 1 == block.slot {
            return Ok(Gwei::ZERO);
        }
        let start = parent_slot + 1;
        let end = block.slot.saturating_sub(1);
        let parent = store
            .blocks
            .ancestor(root, parent_slot)
            .unwrap_or(block.parent_root);
        let support =
            Self::node_support_between_slots(store, balance_source, parent, start, end, head)?;
        let adversarial =
            Self::compute_adversarial_weight(store, balance_source, start, end, head)?;
        Ok(support.saturating_sub(adversarial))
    }

    /// Stake of the committees of a slot range voting exactly for a block.
    ///
    /// See `get_node_support_between_slots` in the phase0 fast confirmation spec.
    fn node_support_between_slots<P: Preset>(
        store: &Store<P>,
        balance_source: &BeaconState<P>,
        node: Root,
        start: Slot,
        end: Slot,
        head: Root,
    ) -> Result<Gwei, ForkChoiceError> {
        let epoch = balance_source.current_epoch();
        let support = Self::committee_members(store, start, end, head)?
            .into_iter()
            .filter_map(|index| {
                let validator = balance_source.validators.get(index.as_usize())?;
                let votes_for_node = store
                    .votes
                    .counted(index)
                    .is_some_and(|message| message.root == node);
                (!validator.slashed && validator.is_active_at(epoch) && votes_for_node)
                    .then_some(validator.effective_balance)
            })
            .sum();
        Ok(support)
    }

    /// Most adversarial weight in a slot range's committees, less known equivocators.
    ///
    /// Threshold: the configured byzantine percentage of the range's committee weight.
    /// See `compute_adversarial_weight` in the phase0 fast confirmation spec.
    fn compute_adversarial_weight<P: Preset>(
        store: &Store<P>,
        balance_source: &BeaconState<P>,
        start: Slot,
        end: Slot,
        head: Root,
    ) -> Result<Gwei, ForkChoiceError> {
        let total = balance_source.total_active_balance();
        let maximum = Self::estimate_committee_weight::<P>(total, start, end);
        let adversarial = maximum / 100 * store.config.confirmation_byzantine_threshold;

        let epoch = balance_source.current_epoch();
        let equivocating: Gwei = Self::committee_members(store, start, end, head)?
            .into_iter()
            .filter(|index| store.votes.is_equivocating(*index))
            .filter_map(|index| balance_source.validators.get(index.as_usize()))
            .filter(|validator| validator.is_active_at(epoch))
            .map(|validator| validator.effective_balance)
            .sum();
        Ok(adversarial.saturating_sub(equivocating))
    }

    /// Estimated committee weight of a slot range.
    ///
    /// # Algorithm
    ///
    /// A range covering a full epoch holds the whole validator set.
    /// A range within one epoch holds one committee per slot.
    ///
    /// A range straddling a boundary is pro-rated: the start epoch's slots count only for the
    /// share of validators not yet seen in the end epoch.
    /// The result is then raised by half a percent to stay safe with high probability.
    ///
    /// See `estimate_committee_weight_between_slots` in the phase0 fast confirmation spec.
    fn estimate_committee_weight<P: Preset>(total: Gwei, start: Slot, end: Slot) -> Gwei {
        if start > end {
            return Gwei::ZERO;
        }
        let full_epoch_covered =
            (start + (P::SLOTS_PER_EPOCH - 1)).epoch::<P>() < (end + 1).epoch::<P>();
        if full_epoch_covered {
            return total;
        }
        let committee_weight = total / P::SLOTS_PER_EPOCH;
        let (start_epoch, end_epoch) = (start.epoch::<P>(), end.epoch::<P>());
        if start_epoch == end_epoch {
            return committee_weight * (end - start + 1);
        }

        let slots_in_end_epoch = end.index_in_epoch::<P>() + 1;
        let remaining_in_end_epoch = P::SLOTS_PER_EPOCH - slots_in_end_epoch;
        let slots_in_start_epoch = P::SLOTS_PER_EPOCH - start.index_in_epoch::<P>();
        let start_weight = committee_weight * slots_in_start_epoch;
        let end_weight = committee_weight * slots_in_end_epoch;
        let start_pro_rated = start_weight / P::SLOTS_PER_EPOCH * remaining_in_end_epoch;

        // Round up to whole thousandths, then add the adjustment factor.
        let estimate = start_pro_rated + end_weight;
        Gwei(estimate.0.div_ceil(1000) * (1000 + COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR))
    }

    /// Whether honest votes alone keep any conflicting checkpoint from justification.
    ///
    /// See `will_no_conflicting_checkpoint_be_justified` in the phase0 fast confirmation spec.
    fn will_no_conflicting_checkpoint_be_justified<P: Preset>(
        store: &Store<P>,
        head: Root,
    ) -> Result<bool, ForkChoiceError> {
        if Self::current_target(store, head)? == store.unrealized_justified_checkpoint {
            return Ok(true);
        }
        let state = Self::pulled_up_head_state(store, head)?;
        let total = state.beacon().total_active_balance();
        let honest = Self::honest_ffg_support_for_current_target(store, &state, head)?;
        // Threshold: more than a third of honest support blocks any other justification.
        Ok(u128::from(honest.0) * 3 > u128::from(total.0))
    }

    /// Whether honest votes alone will justify the current target.
    ///
    /// See `will_current_target_be_justified` in the phase0 fast confirmation spec.
    fn will_current_target_be_justified<P: Preset>(
        store: &Store<P>,
        head: Root,
    ) -> Result<bool, ForkChoiceError> {
        let state = Self::pulled_up_head_state(store, head)?;
        let total = state.beacon().total_active_balance();
        let honest = Self::honest_ffg_support_for_current_target(store, &state, head)?;
        // Threshold: two thirds of the stake.
        Ok(u128::from(honest.0) * 3 >= u128::from(total.0) * 2)
    }

    /// Lower bound on the honest FFG support the current target will collect this epoch.
    ///
    /// Support seen so far, less the adversary's share, plus the honest share of slots to come.
    /// See `compute_honest_ffg_support_for_current_target` in the phase0 fast confirmation spec.
    fn honest_ffg_support_for_current_target<P: Preset>(
        store: &Store<P>,
        state: &State<P>,
        head: Root,
    ) -> Result<Gwei, ForkChoiceError> {
        let current_slot = store.current_slot();
        let epoch_start = current_slot.epoch::<P>().start_slot::<P>();
        let beacon = state.beacon();
        let total = beacon.total_active_balance();

        let support = Self::current_target_score(store, beacon, head)?;
        let weight_so_far = Self::estimate_committee_weight::<P>(
            total,
            epoch_start,
            current_slot.saturating_sub(1),
        );
        let remaining = total.saturating_sub(weight_so_far);
        let remaining_honest =
            remaining / 100 * (100 - store.config.confirmation_byzantine_threshold);
        let adversarial = Self::compute_adversarial_weight(
            store,
            beacon,
            epoch_start,
            current_slot.saturating_sub(1),
            head,
        )?;
        Ok(support.saturating_sub(adversarial) + remaining_honest)
    }

    /// FFG support of the current target, estimated from LMD-GHOST votes.
    ///
    /// See `get_current_target_score` in the phase0 fast confirmation spec.
    fn current_target_score<P: Preset>(
        store: &Store<P>,
        state: &BeaconState<P>,
        head: Root,
    ) -> Result<Gwei, ForkChoiceError> {
        let target = Self::current_target(store, head)?;
        let epoch = state.current_epoch();
        let mut score = Gwei::ZERO;
        for (index, validator) in state.validators.iter().enumerate() {
            if !validator.is_active_at(epoch) || validator.slashed {
                continue;
            }
            if let Some(message) = store.votes.counted(ValidatorIndex::from(index))
                && store.checkpoint_block(message.root, message.epoch) == Some(target.root)
                && message.epoch == target.epoch
            {
                score += validator.effective_balance;
            }
        }
        Ok(score)
    }

    /// The current epoch's checkpoint on the head's chain.
    fn current_target<P: Preset>(
        store: &Store<P>,
        head: Root,
    ) -> Result<Checkpoint, ForkChoiceError> {
        let epoch = store.current_epoch();
        let root = store
            .checkpoint_block(head, epoch)
            .ok_or(ForkChoiceError::MissingState(head))?;
        Ok(Checkpoint { epoch, root })
    }

    /// The head's state, advanced to the current epoch when it lags behind.
    ///
    /// See `get_pulled_up_head_state` in the phase0 fast confirmation spec.
    fn pulled_up_head_state<P: Preset>(
        store: &Store<P>,
        head: Root,
    ) -> Result<State<P>, ForkChoiceError> {
        let mut state = store
            .block_states
            .get(&head)
            .cloned()
            .ok_or(ForkChoiceError::MissingState(head))?;
        let epoch = store.current_epoch();
        if state.beacon().current_epoch() < epoch {
            state.process_slots(&store.config, epoch.start_slot::<P>())?;
        }
        Ok(state)
    }

    /// The state that weighs votes for a checkpoint.
    fn balance_source<P: Preset>(
        store: &mut Store<P>,
        checkpoint: Checkpoint,
    ) -> Result<BeaconState<P>, ForkChoiceError> {
        Ok(store.checkpoint_state(checkpoint)?.beacon().clone())
    }

    /// Members of every committee in a slot range, by the head's shuffling.
    ///
    /// See `get_slot_committee` in the phase0 fast confirmation spec.
    fn committee_members<P: Preset>(
        store: &Store<P>,
        start: Slot,
        end: Slot,
        head: Root,
    ) -> Result<HashSet<ValidatorIndex>, ForkChoiceError> {
        let mut members = HashSet::new();
        if start > end {
            return Ok(members);
        }
        let state = store
            .block_states
            .get(&head)
            .ok_or(ForkChoiceError::MissingState(head))?;
        let mut cached: Option<EpochCommittees> = None;
        for slot in start.0..=end.0 {
            let slot = Slot(slot);
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

    /// Canonical-chain blocks after one block, up to and including another.
    ///
    /// Returns nothing when the first is not an ancestor of the second.
    /// See `get_ancestor_roots` in the phase0 fast confirmation spec.
    fn ancestor_roots<P: Preset>(store: &Store<P>, root: Root, terminal: Root) -> Vec<Root> {
        let terminal_slot = Self::block_slot(store, terminal);
        let mut roots = Vec::new();
        let mut current = root;
        while let Some(node) = store.blocks.get(&current) {
            if node.slot <= terminal_slot {
                break;
            }
            roots.push(current);
            current = node.parent_root;
            if current == terminal {
                roots.reverse();
                return roots;
            }
        }
        Vec::new()
    }

    /// Slot of a stored block, genesis when unknown.
    fn block_slot<P: Preset>(store: &Store<P>, root: Root) -> Slot {
        store
            .blocks
            .get(&root)
            .map_or(Slot::GENESIS, |node| node.slot)
    }

    /// Epoch of a stored block.
    fn block_epoch<P: Preset>(store: &Store<P>, root: Root) -> Epoch {
        Self::block_slot(store, root).epoch::<P>()
    }
}
