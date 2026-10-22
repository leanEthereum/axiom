//! The fork choice store: what a node knows, and the clock it knows it by.

use std::collections::HashMap;

use axiom_ssz::Ssz;
use axiom_state_transition::State;
use axiom_types::{
    BeaconBlock, BeaconState, ChainConfig, Checkpoint, Epoch, Gwei, Preset, Root, Slot,
};

use crate::{BlockNode, BlockTree, ForkChoiceError, Votes};

/// Basis points in a whole, the unit slot deadlines are expressed in.
pub(crate) const BASIS_POINTS: u64 = 10_000;

/// Everything the fork choice rule reads: blocks, states, votes, checkpoints, and time.
///
/// # Overview
///
/// The store is a pure state machine driven by four kinds of events.
///
/// ```text
/// on_tick              time advances
/// on_block             a block arrives
/// on_attestation       a vote arrives
/// on_attester_slashing equivocators are proven
/// ```
///
/// The head is a pure function of the store, see `get_head` in the phase0 fork choice spec.
///
/// # Invariants
///
/// Every block in the tree has its post-state stored.
/// A handler that fails leaves the store unchanged.
#[derive(Clone, Debug)]
pub struct Store<P: Preset> {
    /// The chain configuration.
    pub(crate) config: ChainConfig,
    /// Current time, in milliseconds since the Unix epoch.
    pub(crate) time_ms: u64,
    /// Genesis time, in milliseconds since the Unix epoch.
    pub(crate) genesis_time_ms: u64,
    /// Justified checkpoint LMD-GHOST starts from.
    pub(crate) justified_checkpoint: Checkpoint,
    /// Latest finalized checkpoint, which no head may conflict with.
    pub(crate) finalized_checkpoint: Checkpoint,
    /// Best justified checkpoint seen, counting votes not yet processed on chain.
    pub(crate) unrealized_justified_checkpoint: Checkpoint,
    /// Best finalized checkpoint seen, counting votes not yet processed on chain.
    pub(crate) unrealized_finalized_checkpoint: Checkpoint,
    /// Block that holds the proposer boost in the current slot, or zero.
    pub(crate) proposer_boost_root: Root,
    /// Accepted blocks.
    pub(crate) blocks: BlockTree,
    /// Post-state of each accepted block.
    pub(crate) block_states: HashMap<Root, State<P>>,
    /// Whether each block arrived on time in its own slot.
    pub(crate) block_timeliness: HashMap<Root, bool>,
    /// States at checkpoint boundaries, by checkpoint.
    pub(crate) checkpoint_states: HashMap<Checkpoint, State<P>>,
    /// Latest votes and equivocators.
    pub(crate) votes: Votes,
    /// Justified checkpoint each block would realize at its next epoch boundary.
    pub(crate) unrealized_justifications: HashMap<Root, Checkpoint>,
}

impl<P: Preset> Store<P> {
    /// A store anchored at a trusted state and the block it is the post-state of.
    ///
    /// The anchor is genesis for a full sync, or a finalized checkpoint for a checkpoint sync.
    /// See `get_forkchoice_store` in the phase0 fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the block does not commit to the state.
    pub fn new(
        config: ChainConfig,
        anchor_state: BeaconState<P>,
        anchor_block: &BeaconBlock<P>,
    ) -> Result<Self, ForkChoiceError> {
        if anchor_block.state_root != anchor_state.hash_tree_root() {
            return Err(ForkChoiceError::AnchorMismatch);
        }
        let anchor_root = anchor_block.hash_tree_root();
        let checkpoint = Checkpoint {
            epoch: anchor_state.current_epoch(),
            root: anchor_root,
        };
        let genesis_time_ms = anchor_state.genesis_time.saturating_mul(1000);
        let time_ms = genesis_time_ms + anchor_state.slot.0 * config.slot_duration_ms;
        let state = State::new(anchor_state);

        Ok(Self {
            config,
            time_ms,
            genesis_time_ms,
            justified_checkpoint: checkpoint,
            finalized_checkpoint: checkpoint,
            unrealized_justified_checkpoint: checkpoint,
            unrealized_finalized_checkpoint: checkpoint,
            proposer_boost_root: Root::ZERO,
            blocks: BlockTree::new(
                anchor_root,
                BlockNode {
                    slot: anchor_block.slot,
                    parent_root: anchor_block.parent_root,
                    proposer_index: anchor_block.proposer_index,
                    execution_block_hash: anchor_block.body.execution_payload.block_hash,
                },
            ),
            block_states: HashMap::from([(anchor_root, state.clone())]),
            block_timeliness: HashMap::new(),
            checkpoint_states: HashMap::from([(checkpoint, state)]),
            votes: Votes::default(),
            unrealized_justifications: HashMap::from([(anchor_root, checkpoint)]),
        })
    }

    /// Current time, in milliseconds since the Unix epoch.
    #[must_use]
    pub const fn time_ms(&self) -> u64 {
        self.time_ms
    }

    /// Genesis time, in milliseconds since the Unix epoch.
    #[must_use]
    pub const fn genesis_time_ms(&self) -> u64 {
        self.genesis_time_ms
    }

    /// Justified checkpoint LMD-GHOST starts from.
    #[must_use]
    pub const fn justified_checkpoint(&self) -> Checkpoint {
        self.justified_checkpoint
    }

    /// Latest finalized checkpoint.
    #[must_use]
    pub const fn finalized_checkpoint(&self) -> Checkpoint {
        self.finalized_checkpoint
    }

    /// Block holding the proposer boost, or zero.
    #[must_use]
    pub const fn proposer_boost_root(&self) -> Root {
        self.proposer_boost_root
    }

    /// The tree of accepted blocks.
    #[must_use]
    pub const fn blocks(&self) -> &BlockTree {
        &self.blocks
    }

    /// Post-state of an accepted block.
    #[must_use]
    pub fn block_state(&self, root: &Root) -> Option<&State<P>> {
        self.block_states.get(root)
    }

    /// The slot the clock is in.
    ///
    /// See `get_current_slot` in the phase0 fork choice spec.
    #[must_use]
    pub const fn current_slot(&self) -> Slot {
        Slot(self.time_ms.saturating_sub(self.genesis_time_ms) / self.config.slot_duration_ms)
    }

    /// The epoch the clock is in.
    #[must_use]
    pub const fn current_epoch(&self) -> Epoch {
        self.current_slot().epoch::<P>()
    }

    /// Milliseconds since the current slot started.
    #[must_use]
    pub const fn time_into_slot_ms(&self) -> u64 {
        self.time_ms - self.slot_start_ms(self.current_slot())
    }

    /// Advances the clock, running the per-slot updates of every slot it crosses.
    ///
    /// See `on_tick` in the phase0 fork choice spec.
    pub fn on_tick(&mut self, time_ms: u64) {
        let tick_slot =
            Slot(time_ms.saturating_sub(self.genesis_time_ms) / self.config.slot_duration_ms);
        while self.current_slot() < tick_slot {
            let next = self.slot_start_ms(self.current_slot() + 1);
            self.on_tick_per_slot(next);
        }
        self.on_tick_per_slot(time_ms);
    }

    /// Moves the clock within one slot, or onto the start of the next.
    ///
    /// A new slot clears the proposer boost.
    /// A new epoch realizes the checkpoints that were only pulled up so far.
    fn on_tick_per_slot(&mut self, time_ms: u64) {
        let previous_slot = self.current_slot();
        self.time_ms = time_ms;
        let current_slot = self.current_slot();

        if current_slot > previous_slot {
            self.proposer_boost_root = Root::ZERO;
            if current_slot.is_epoch_start::<P>() {
                self.update_checkpoints(
                    self.unrealized_justified_checkpoint,
                    self.unrealized_finalized_checkpoint,
                );
            }
        }
    }

    /// Adopts checkpoints that are newer than the store's.
    ///
    /// See `update_checkpoints` in the phase0 fork choice spec.
    pub(crate) fn update_checkpoints(&mut self, justified: Checkpoint, finalized: Checkpoint) {
        if justified.epoch > self.justified_checkpoint.epoch {
            self.justified_checkpoint = justified;
        }
        if finalized.epoch > self.finalized_checkpoint.epoch {
            self.finalized_checkpoint = finalized;
        }
    }

    /// Adopts unrealized checkpoints that are newer than the store's.
    pub(crate) fn update_unrealized_checkpoints(
        &mut self,
        justified: Checkpoint,
        finalized: Checkpoint,
    ) {
        if justified.epoch > self.unrealized_justified_checkpoint.epoch {
            self.unrealized_justified_checkpoint = justified;
        }
        if finalized.epoch > self.unrealized_finalized_checkpoint.epoch {
            self.unrealized_finalized_checkpoint = finalized;
        }
    }

    /// Start of a slot, in milliseconds since the Unix epoch.
    pub(crate) const fn slot_start_ms(&self, slot: Slot) -> u64 {
        self.genesis_time_ms + slot.0 * self.config.slot_duration_ms
    }

    /// Length of a slot component given in basis points of the slot.
    pub(crate) const fn slot_component_ms(&self, basis_points: u64) -> u64 {
        basis_points * self.config.slot_duration_ms / BASIS_POINTS
    }

    /// The block that is the checkpoint of an epoch on a block's chain.
    ///
    /// See `get_checkpoint_block` in the phase0 fork choice spec.
    #[must_use]
    pub fn checkpoint_block(&self, root: Root, epoch: Epoch) -> Option<Root> {
        self.blocks.ancestor(root, epoch.start_slot::<P>())
    }

    /// The state at a checkpoint: its block's post-state, advanced to the epoch start.
    ///
    /// See `store_target_checkpoint_state` in the phase0 fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the checkpoint block's state is missing.
    pub(crate) fn checkpoint_state(
        &mut self,
        checkpoint: Checkpoint,
    ) -> Result<&mut State<P>, ForkChoiceError> {
        if !self.checkpoint_states.contains_key(&checkpoint) {
            let mut state = self
                .block_states
                .get(&checkpoint.root)
                .ok_or(ForkChoiceError::MissingState(checkpoint.root))?
                .clone();
            let start = checkpoint.epoch.start_slot::<P>();
            if state.beacon().slot < start {
                state.process_slots(&self.config, start)?;
            }
            self.checkpoint_states.insert(checkpoint, state);
        }
        self.checkpoint_states
            .get_mut(&checkpoint)
            .ok_or(ForkChoiceError::MissingState(checkpoint.root))
    }

    /// A share of one slot's committee weight in a state, as a percentage.
    ///
    /// Proposer boost and the reorg thresholds are expressed this way.
    /// Slashed validators do not count.
    ///
    /// See `calculate_committee_fraction` in the phase0 fork choice spec.
    #[must_use]
    pub fn committee_fraction(state: &BeaconState<P>, percent: u64) -> Gwei {
        let epoch = state.current_epoch();
        let total: Gwei = state
            .validators
            .iter()
            .filter(|validator| validator.is_active_at(epoch) && !validator.slashed)
            .map(|validator| validator.effective_balance)
            .sum();
        let committee_weight = total.max(P::EFFECTIVE_BALANCE_INCREMENT) / P::SLOTS_PER_EPOCH;
        committee_weight * percent / 100
    }
}
