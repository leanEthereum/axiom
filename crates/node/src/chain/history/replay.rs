//! Past states rebuilt by replaying finalized blocks from the nearest snapshot.

use std::collections::VecDeque;

use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{Preset, Slot, accessors::CoreState};

use crate::{ChainDatabase, ChainError, StoredBlock};

/// Rebuilds finalized states, keeping the most recent results.
///
/// # Overview
///
/// A state at slot s is the nearest stored state at or before s, carried forward.
///
/// 1. Take the nearest base: a recent result or a snapshot, whichever is later.
/// 2. Apply each finalized block after the base, up to s.
/// 3. Run the empty slots up to s, epoch transitions and upgrades included.
///
/// Finalized blocks were verified on import or backfill, so replay skips their signatures.
/// Each block's state root is still checked, which pins the result to the chain.
/// The execution payloads are finalized too, so the engine's verdict is taken as valid.
///
/// Finalized states never change, so the kept results never go stale.
#[derive(Clone, Debug)]
pub struct StateReplay<P: Preset> {
    /// The latest results, oldest first.
    recent: VecDeque<State<P>>,
    /// Most results kept.
    capacity: usize,
}

impl<P: Preset> StateReplay<P> {
    /// Results kept by default.
    ///
    /// A beacon API client tends to walk nearby slots, so a few results serve most repeats.
    /// Persistent collections share structure, so the copies cost far less than full states.
    pub const DEFAULT_CAPACITY: usize = 4;

    /// A replayer keeping some results.
    #[must_use]
    pub const fn new(capacity: usize) -> Self {
        Self {
            recent: VecDeque::new(),
            capacity,
        }
    }

    /// The finalized state at a slot, or nothing when no stored state precedes it.
    ///
    /// The slot must not be past the finalized block: later blocks are not in the index.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable, or a stored block does not apply.
    pub fn state_at_slot(
        &mut self,
        database: &ChainDatabase<P>,
        slot: Slot,
    ) -> Result<Option<State<P>>, ChainError> {
        let cached = self
            .recent
            .iter()
            .filter(|state| state.beacon().slot() <= slot)
            .max_by_key(|state| state.beacon().slot());
        if let Some(state) = cached
            && state.beacon().slot() == slot
        {
            return Ok(Some(state.clone()));
        }
        let snapshot_slot = database.snapshot_slot_before(slot)?;
        let mut state = match (cached, snapshot_slot) {
            (Some(state), Some(stored)) if state.beacon().slot() >= stored => state.clone(),
            (_, Some(_)) => match database.snapshot_before(slot)? {
                Some(snapshot) => State::new(snapshot),
                None => return Ok(None),
            },
            (Some(state), None) => state.clone(),
            (None, None) => return Ok(None),
        };
        Self::advance(database, &mut state, slot)?;
        self.keep(state.clone());
        Ok(Some(state))
    }

    /// Carries a state forward through the finalized blocks, up to a slot.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable, or a stored block does not apply.
    pub(crate) fn advance(
        database: &ChainDatabase<P>,
        state: &mut State<P>,
        slot: Slot,
    ) -> Result<(), ChainError> {
        let config = database.config();
        let from = state.beacon().slot() + 1;
        for (block_slot, root) in database.canonical_range(from, slot + 1)? {
            // A block whose payload was pruned replays from its header, to the same state.
            let applied = match database
                .stored_block(root)?
                .ok_or(ChainError::Missing("finalized block"))?
            {
                StoredBlock::Full(block) => {
                    state.state_transition(config, &block, Verification::Skip, &KnownVerdict(true))
                }
                StoredBlock::Blinded(block) => {
                    state.state_transition(config, &block, Verification::Skip, &KnownVerdict(true))
                }
            };
            applied.map_err(|source| ChainError::Replay {
                slot: block_slot,
                source,
            })?;
        }
        if state.beacon().slot() < slot {
            state
                .process_slots(config, slot)
                .map_err(|source| ChainError::ReplaySlots { slot, source })?;
        }
        Ok(())
    }

    /// Keeps a result, dropping the oldest beyond the capacity.
    fn keep(&mut self, state: State<P>) {
        if self.capacity == 0 {
            return;
        }
        if self.recent.len() == self.capacity {
            self.recent.pop_front();
        }
        self.recent.push_back(state);
    }
}

impl<P: Preset> Default for StateReplay<P> {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CAPACITY)
    }
}
