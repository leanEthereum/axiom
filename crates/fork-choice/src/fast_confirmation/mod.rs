//! The fast confirmation rule: blocks that stay canonical under synchrony, long before finality.

mod safety;
mod slot_range;
mod target;

use axiom_types::{Checkpoint, Epoch, Hash32, Preset, Root};
use safety::Safety;
use target::CurrentTarget;

use crate::{ForkChoiceError, Store};

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
                store.checkpoints.unrealized_justified();
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
        let stale = store.blocks.slot_of(&confirmed).epoch::<P>() + 1 < current_epoch;
        let off_chain = !store.blocks.is_ancestor(head, confirmed);
        if stale
            || off_chain
            || (is_epoch_start && !self.is_confirmed_chain_safe(store, confirmed)?)
        {
            confirmed = store.checkpoints.finalized().root;
        }

        // Phase 2: restart from the observed justified checkpoint.
        let observed = self.current_epoch_observed_justified_checkpoint;
        let observed_slot = store.blocks.slot_of(&observed.root);
        let restart = is_epoch_start
            && observed_slot.epoch::<P>() + 1 == current_epoch
            && store.unrealized_justifications.get(&head) == Some(&observed)
            && store.blocks.slot_of(&confirmed) < observed_slot;
        if restart {
            confirmed = observed.root;
        }

        // Phase 3: advance.
        if store.blocks.slot_of(&confirmed).epoch::<P>() + 1 >= current_epoch {
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
        let balance_source = store
            .checkpoint_state(self.current_epoch_observed_justified_checkpoint)?
            .beacon()
            .clone();
        let store = &*store;
        let safety = Safety::new(store, &balance_source, head);
        let target = || CurrentTarget::of(store, head);
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
        if store.blocks.slot_of(&confirmed).epoch::<P>() + 1 == current_epoch
            && previous_head_source + 2 >= current_epoch
            && (is_epoch_start
                || (target()?.blocks_conflicting_justification()?
                    && (unrealized(self.previous_slot_head, store) + 1 >= current_epoch
                        || unrealized(head, store) + 1 >= current_epoch)))
        {
            for root in store.blocks.chain_after(confirmed, head) {
                if store.blocks.slot_of(&root).epoch::<P>() == current_epoch
                    || !store.blocks.is_ancestor(self.previous_slot_head, root)
                    || !safety.is_one_confirmed(root)?
                {
                    break;
                }
                confirmed = root;
            }
        }

        // Phase 2: confirm blocks of the current epoch, which needs its target justified.
        if is_epoch_start || unrealized(head, store) + 1 >= current_epoch {
            let mut tentative = confirmed;
            for root in store.blocks.chain_after(confirmed, head) {
                if store.blocks.slot_of(&root).epoch::<P>()
                    > store.blocks.slot_of(&tentative).epoch::<P>()
                    && !target()?.will_be_justified()?
                {
                    break;
                }
                if !safety.is_one_confirmed(root)? {
                    break;
                }
                tentative = root;
            }

            // Confirm only what cannot be filtered out in this epoch or the next.
            let tentative_source = store
                .voting_source(tentative)
                .map_or(Epoch::GENESIS, |source| source.epoch);
            if store.blocks.slot_of(&tentative).epoch::<P>() == current_epoch
                || (tentative_source + 2 >= current_epoch
                    && (is_epoch_start || target()?.blocks_conflicting_justification()?))
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
            if store.blocks.slot_of(&ancestor).epoch::<P>() + 1 == current_epoch {
                store
                    .blocks
                    .get(&ancestor)
                    .map_or(ancestor, |node| node.parent_root)
            } else {
                ancestor
            }
        };

        let balance_source = store
            .checkpoint_state(self.previous_epoch_observed_justified_checkpoint)?
            .beacon()
            .clone();
        let safety = Safety::new(store, &balance_source, self.current_slot_head);
        for root in store.blocks.chain_after(start_exclusive, confirmed) {
            if !safety.is_one_confirmed(root)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
