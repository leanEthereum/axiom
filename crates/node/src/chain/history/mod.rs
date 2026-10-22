//! The chain's past: states at any slot, backfilled blocks, rebuilt snapshots, weak subjectivity.

mod replay;
mod segment;
mod weak_subjectivity;

use std::collections::HashMap;

use axiom_fork_choice::Store;
use axiom_state_transition::State;
use axiom_types::{Preset, Root, Slot, accessors::CoreState, combined, phase0::Checkpoint};
pub use replay::StateReplay;
pub use segment::{HistorySegment, ProposerKeys, SegmentContext, SegmentError, VerifiedSegment};
pub use weak_subjectivity::{WeakSubjectivity, WeakSubjectivityError};

use super::{ChainDatabase, ReconstructionCursor};
use crate::ChainError;

/// How far one rebuild step went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reconstruction {
    /// Every past state is reachable from a nearby snapshot, or nothing needs rebuilding.
    Done,
    /// Rebuilding waits for backfill to reach genesis, or for a genesis state.
    Waiting,
    /// States up to a slot are rebuilt, and more remain.
    Progressed(Slot),
}

/// What an archive writes for a stretch of finalized history.
#[derive(Debug)]
pub(crate) struct ArchiveRecords<P: Preset> {
    /// States at the snapshot slots passed.
    pub(crate) snapshots: Vec<combined::BeaconState<P>>,
    /// Roots of the states passed, with their slots.
    pub(crate) state_roots: Vec<(Root, Slot)>,
}

impl<P: Preset> Default for ArchiveRecords<P> {
    fn default() -> Self {
        Self {
            snapshots: Vec::new(),
            state_roots: Vec::new(),
        }
    }
}

/// What the chain keeps about its past, beside the database.
///
/// # Overview
///
/// - Replay rebuilds finalized states from snapshots and keeps the latest results.
/// - The roots of states since finality map to their blocks, for lookups by state root.
/// - A rebuild in progress keeps its state between steps.
/// - The operator's weak subjectivity checkpoint waits here until the chain settles it.
#[derive(Debug)]
pub(crate) struct History<P: Preset> {
    /// Rebuilt finalized states.
    replay: StateReplay<P>,
    /// Block root of each state root since finality.
    hot_roots: HashMap<Root, Root>,
    /// The state a rebuild reached, between steps.
    rebuilding: Option<State<P>>,
    /// The trusted checkpoint, until the chain passes it.
    weak_subjectivity: Option<WeakSubjectivity>,
}

impl<P: Preset> History<P> {
    /// No past known yet beyond an anchor block and its state root.
    pub(crate) fn new(anchor: Root, anchor_state_root: Root) -> Self {
        Self {
            replay: StateReplay::default(),
            hot_roots: HashMap::from([(anchor_state_root, anchor)]),
            rebuilding: None,
            weak_subjectivity: None,
        }
    }

    /// Records the state root of a block the fork choice now holds.
    pub(crate) fn note_block(&mut self, state_root: Root, block: Root) {
        self.hot_roots.insert(state_root, block);
    }

    /// Forgets the state roots of blocks the fork choice no longer holds.
    pub(crate) fn prune(&mut self, store: &Store<P>) {
        self.hot_roots
            .retain(|_, block| store.blocks().contains(block));
    }

    /// Waits for the chain to pass a trusted checkpoint.
    pub(crate) const fn trust(&mut self, checkpoint: WeakSubjectivity) {
        self.weak_subjectivity = Some(checkpoint);
    }

    /// The trusted checkpoint the chain has not passed yet.
    pub(crate) const fn weak_subjectivity(&self) -> Option<WeakSubjectivity> {
        self.weak_subjectivity
    }

    /// Settles the trusted checkpoint against the canonical block at its epoch.
    ///
    /// # Errors
    ///
    /// Fails when the canonical block is another block; the checkpoint then stays pending.
    pub(crate) fn settle(&mut self, canonical: Root) -> Result<(), WeakSubjectivityError> {
        if let Some(checkpoint) = self.weak_subjectivity {
            checkpoint.check_block(canonical)?;
            self.weak_subjectivity = None;
        }
        Ok(())
    }

    /// The state at a slot of the canonical chain, up to the head.
    ///
    /// Since finality the fork choice holds the states, and empty slots run on from them.
    /// Before it, replay rebuilds them from the database.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable, or a stored block does not apply.
    pub(crate) fn state_at_slot(
        &mut self,
        store: &Store<P>,
        database: &ChainDatabase<P>,
        head: Root,
        slot: Slot,
    ) -> Result<Option<State<P>>, ChainError> {
        let blocks = store.blocks();
        let Some(head_slot) = blocks.get(&head).map(|node| node.slot) else {
            return Ok(None);
        };
        if slot > head_slot {
            return Ok(None);
        }
        let finalized = store.finalized_checkpoint().root;
        let finalized_slot = blocks.get(&finalized).map_or(Slot(0), |node| node.slot);
        if slot < finalized_slot {
            return self.replay.state_at_slot(database, slot);
        }
        let Some(state) = blocks
            .ancestor(head, slot)
            .and_then(|root| store.block_state(&root))
        else {
            return Ok(None);
        };
        let mut state = state.clone();
        if state.beacon().slot() < slot {
            state
                .process_slots(store.config(), slot)
                .map_err(|source| ChainError::ReplaySlots { slot, source })?;
        }
        Ok(Some(state))
    }

    /// The state with a root, among the block states since finality and the indexed finalized ones.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable, or a stored block does not apply.
    pub(crate) fn state_by_root(
        &mut self,
        store: &Store<P>,
        database: &ChainDatabase<P>,
        head: Root,
        root: Root,
    ) -> Result<Option<State<P>>, ChainError> {
        if let Some(state) = self
            .hot_roots
            .get(&root)
            .and_then(|block| store.block_state(block))
        {
            return Ok(Some(state.clone()));
        }
        match database.state_root_slot(root)? {
            Some(slot) => self.state_at_slot(store, database, head, slot),
            None => Ok(None),
        }
    }

    /// The archive records a new finality adds: snapshots at due slots, and state roots.
    ///
    /// # Arguments
    ///
    /// - `previous`: the superseded finalized checkpoint, whose state the store still holds.
    /// - `chain`: the newly finalized blocks, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the store lacks a state on the finalized chain, or an empty slot fails to run.
    pub(crate) fn finality_records(
        store: &Store<P>,
        database: &ChainDatabase<P>,
        previous: Checkpoint,
        chain: &[(Slot, Root)],
    ) -> Result<ArchiveRecords<P>, ChainError> {
        let (Some(interval), Some(&(new_slot, new_root))) =
            (database.mode().interval(), chain.first())
        else {
            return Ok(ArchiveRecords::default());
        };
        let previous_slot = store
            .blocks()
            .get(&previous.root)
            .map_or(Slot(0), |node| node.slot);
        let state_of = |root: Root| {
            store
                .block_state(&root)
                .ok_or(ChainError::MissingState(root))
        };

        // Snapshots at each due slot the finality passed, each from the latest block before it.
        let mut snapshots = Vec::new();
        let first_due = (previous_slot.0 / interval.slots() + 1) * interval.slots();
        for due in (first_due..=new_slot.0).step_by(interval.slots() as usize) {
            let due = Slot(due);
            let root = chain
                .iter()
                .find(|(slot, _)| *slot <= due)
                .map_or(previous.root, |(_, root)| *root);
            let mut state = state_of(root)?.clone();
            if state.beacon().slot() < due {
                state
                    .process_slots(store.config(), due)
                    .map_err(|source| ChainError::ReplaySlots { slot: due, source })?;
            }
            snapshots.push(state.into_beacon());
        }

        // The finalized state lists the roots of the recent states before it, slot by slot.
        let state = state_of(new_root)?.beacon();
        let window = P::SLOTS_PER_HISTORICAL_ROOT;
        let oldest = (previous_slot.0 + 1).max(new_slot.0.saturating_sub(window));
        let mut state_roots: Vec<(Root, Slot)> = (oldest..new_slot.0)
            .map(|slot| (state.state_roots()[(slot % window) as usize], Slot(slot)))
            .collect();
        state_roots.push((state.hash_tree_root(), new_slot));
        Ok(ArchiveRecords {
            snapshots,
            state_roots,
        })
    }

    /// Rebuilds the snapshots of a backfilled range, a bounded number of slots at a time.
    ///
    /// # Overview
    ///
    /// A checkpoint sync in archive mode stores snapshots from its anchor on.
    /// Once backfill reaches genesis, replay from the genesis state fills the range below.
    ///
    /// 1. Start from the state the last step reached, or the latest snapshot before it.
    /// 2. Replay up to the budget, storing a snapshot at each due slot.
    /// 3. Index the roots of every state passed, read from the state's own root history.
    ///
    /// The budget is capped at the root history's length, so every passed root is still listed.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable, a block does not apply, or the genesis state is wrong.
    pub(crate) fn reconstruct(
        &mut self,
        database: &ChainDatabase<P>,
        budget: u64,
    ) -> Result<Reconstruction, ChainError> {
        let Some(cursor) = database.reconstruction()? else {
            return Ok(Reconstruction::Done);
        };
        let (Some(interval), true) = (database.mode().interval(), cursor.reached < cursor.target)
        else {
            return Ok(Reconstruction::Done);
        };
        if !database
            .history_start()?
            .is_some_and(|start| start.reaches_genesis())
        {
            return Ok(Reconstruction::Waiting);
        }
        let mut state = match self.rebuilding.take() {
            Some(state) if state.beacon().slot() == cursor.reached => state,
            _ => match database.snapshot_before(cursor.reached)? {
                Some(snapshot) => State::new(snapshot),
                None => return Ok(Reconstruction::Waiting),
            },
        };
        let start = state.beacon().slot();
        if start == Slot(0) {
            Self::check_genesis(database, &state)?;
        }

        let budget = budget.clamp(1, P::SLOTS_PER_HISTORICAL_ROOT);
        let end = Slot(cursor.target.0.min(start.0.saturating_add(budget)));
        let mut snapshots = Vec::new();
        let first_due = (start.0 / interval.slots() + 1) * interval.slots();
        // The target already has its snapshot, written with the anchor.
        for due in (first_due..end.0).step_by(interval.slots() as usize) {
            StateReplay::advance(database, &mut state, Slot(due))?;
            snapshots.push(state.beacon().clone());
        }
        StateReplay::advance(database, &mut state, end)?;

        let beacon = state.beacon();
        let window = P::SLOTS_PER_HISTORICAL_ROOT;
        let mut state_roots: Vec<(Root, Slot)> = (start.0..end.0)
            .map(|slot| (beacon.state_roots()[(slot % window) as usize], Slot(slot)))
            .collect();
        state_roots.push((beacon.hash_tree_root(), end));
        let reached = ReconstructionCursor {
            reached: end,
            target: cursor.target,
        };
        database.put_reconstruction(&snapshots, &state_roots, reached)?;
        if end >= cursor.target {
            return Ok(Reconstruction::Done);
        }
        self.rebuilding = Some(state);
        Ok(Reconstruction::Progressed(end))
    }

    /// Checks a genesis state against the genesis block's state root.
    ///
    /// # Errors
    ///
    /// Fails when the genesis block is unknown, or names another state.
    pub(crate) fn check_genesis(
        database: &ChainDatabase<P>,
        genesis: &State<P>,
    ) -> Result<(), ChainError> {
        let root = database
            .canonical_root(Slot(0))?
            .ok_or(ChainError::Missing("genesis block"))?;
        let block = database
            .block(root)?
            .ok_or(ChainError::Missing("genesis block"))?;
        let expected = block.message().state_root();
        let actual = genesis.hash_tree_root();
        if expected == actual {
            Ok(())
        } else {
            Err(ChainError::GenesisMismatch { expected, actual })
        }
    }
}
