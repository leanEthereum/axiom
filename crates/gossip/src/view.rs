//! The node's view of the chain that gossip rules consult.

use std::collections::HashMap;

use axiom_fork_choice::{BlockNode, ExecutionStatus, ForkChoiceError, Store};
use axiom_state_transition::State;
use axiom_types::{ChainConfig, Checkpoint, Epoch, Preset, Root, Slot};

/// Everything gossip validation reads about the chain.
///
/// # Overview
///
/// The fork choice store holds the blocks a node imported, with their post-states.
/// A node also knows blocks it saw but could not import: ones that failed, and ones still queued.
/// Rules about a message's parent distinguish all three.
///
/// ```text
/// known      imported   meaning
/// no         no         never seen: ignore, the parent may arrive
/// yes        no         failed or pending: reject or ignore
/// yes        yes        imported: the rule reads its post-state
/// ```
#[derive(Debug)]
pub struct ChainView<'a, P: Preset> {
    /// The fork choice store, holding imported blocks and their states.
    pub store: &'a mut Store<P>,
    /// Blocks seen but not imported, because they failed or are still queued.
    pub unimported: &'a HashMap<Root, BlockNode>,
    /// Payload validity of blocks, where it differs from the store's own record.
    pub payload_statuses: &'a HashMap<Root, ExecutionStatus>,
    /// Finalized checkpoint the rules respect.
    pub finalized: Checkpoint,
}

impl<'a, P: Preset> ChainView<'a, P> {
    /// A view of a store and no other block, finalized where the store says.
    pub const fn new(
        store: &'a mut Store<P>,
        unimported: &'a HashMap<Root, BlockNode>,
        payload_statuses: &'a HashMap<Root, ExecutionStatus>,
    ) -> Self {
        let finalized = store.finalized_checkpoint();
        Self {
            store,
            unimported,
            payload_statuses,
            finalized,
        }
    }

    /// The chain configuration.
    #[must_use]
    pub const fn config(&self) -> &ChainConfig {
        self.store.config()
    }

    /// A block the node has seen, imported or not.
    #[must_use]
    pub fn block(&self, root: &Root) -> Option<BlockNode> {
        self.store
            .blocks()
            .get(root)
            .or_else(|| self.unimported.get(root))
            .copied()
    }

    /// Whether a block was imported, so its post-state is available.
    #[must_use]
    pub fn is_imported(&self, root: &Root) -> bool {
        self.store.block_state(root).is_some()
    }

    /// Payload validity of a block, unvalidated when nothing is known.
    #[must_use]
    pub fn payload_status(&self, root: &Root) -> Option<ExecutionStatus> {
        self.payload_statuses.get(root).copied().or_else(|| {
            self.store
                .block_state(root)
                .and_then(|_| self.store.blocks().get(root))
                .map(|node| node.status)
        })
    }

    /// Post-state of the head block.
    ///
    /// # Errors
    ///
    /// Fails when the head's state is missing.
    pub fn head_state(&mut self) -> Result<State<P>, ForkChoiceError> {
        let head = self.store.head()?;
        self.store
            .block_state(&head)
            .cloned()
            .ok_or(ForkChoiceError::MissingState(head))
    }

    /// Post-state of an imported block, advanced to a slot.
    ///
    /// # Errors
    ///
    /// Fails when the block is not imported, or advancing fails.
    pub fn state_at(&self, root: &Root, slot: Slot) -> Result<State<P>, ForkChoiceError> {
        let mut state = self
            .store
            .block_state(root)
            .cloned()
            .ok_or(ForkChoiceError::MissingState(*root))?;
        if state.beacon().slot < slot {
            state.process_slots(self.store.config(), slot)?;
        }
        Ok(state)
    }

    /// The checkpoint block of an epoch on a block's chain, through seen blocks too.
    ///
    /// The store's anchor stands for every slot before it, as its tree has no parent for it.
    #[must_use]
    pub fn checkpoint_block(&self, root: Root, epoch: Epoch) -> Option<Root> {
        let target = epoch.start_slot::<P>();
        let mut current = root;
        loop {
            let node = self.block(&current)?;
            let at_anchor =
                self.store.blocks().contains(&current) && self.block(&node.parent_root).is_none();
            if node.slot <= target || at_anchor {
                return Some(current);
            }
            current = node.parent_root;
        }
    }

    /// Whether the finalized checkpoint is on a block's chain.
    #[must_use]
    pub fn descends_from_finalized(&self, root: Root) -> bool {
        self.checkpoint_block(root, self.finalized.epoch) == Some(self.finalized.root)
    }

    /// Start of a slot, in milliseconds since the Unix epoch.
    #[must_use]
    pub const fn slot_start_ms(&self, slot: Slot) -> u64 {
        self.store.genesis_time_ms() + slot.0 * self.config().slot_duration_ms
    }

    /// Whether a slot starts after the current time plus the allowed clock disparity.
    ///
    /// See `is_future_slot` in the phase0 p2p spec.
    #[must_use]
    pub const fn is_future_slot(&self, slot: Slot, now_ms: u64) -> bool {
        now_ms + self.config().maximum_gossip_clock_disparity_ms < self.slot_start_ms(slot)
    }

    /// Whether an epoch starts after the current time plus the allowed clock disparity.
    #[must_use]
    pub fn is_future_epoch(&self, epoch: Epoch, now_ms: u64) -> bool {
        let shifted = now_ms + self.config().maximum_gossip_clock_disparity_ms;
        let slot = Slot(
            shifted.saturating_sub(self.store.genesis_time_ms()) / self.config().slot_duration_ms,
        );
        slot.epoch::<P>() < epoch
    }

    /// Whether the current time falls in the slot range from a slot through range more slots.
    ///
    /// The clock disparity widens both ends.
    /// See `is_within_slot_range` in the phase0 p2p spec.
    #[must_use]
    pub fn is_within_slot_range(&self, slot: Slot, range: u64, now_ms: u64) -> bool {
        let disparity = self.config().maximum_gossip_clock_disparity_ms;
        let start = self.slot_start_ms(slot);
        let end = self.slot_start_ms(slot + range + 1);
        now_ms + disparity >= start && end + disparity >= now_ms
    }

    /// Whether the current time falls in an epoch.
    #[must_use]
    pub fn is_within_epoch(&self, epoch: Epoch, now_ms: u64) -> bool {
        self.is_within_slot_range(epoch.start_slot::<P>(), P::SLOTS_PER_EPOCH - 1, now_ms)
    }

    /// Whether an epoch is the current or the previous one.
    #[must_use]
    pub fn is_current_or_previous_epoch(&self, epoch: Epoch, now_ms: u64) -> bool {
        self.is_within_epoch(epoch, now_ms) || self.is_within_epoch(epoch + 1, now_ms)
    }
}
