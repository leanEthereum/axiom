//! A beacon state paired with the caches that make processing fast.

mod accessors;
mod mutators;

use std::sync::Arc;

use axiom_ssz::Ssz;
use axiom_types::{BeaconState, ChainConfig, Epoch, Preset, Root, SignedBeaconBlock, Slot};

use crate::{
    BlockProcessor, EpochCommittees, EpochProcessor, ExecutionEngine, PubkeyCache, StateError,
    TransitionError, Verification,
};

/// A beacon state with its derived caches.
///
/// # Overview
///
/// The beacon state is the consensus object, defined field by field by the spec.
/// The caches are derived from it, and never change its meaning or its root.
///
/// Every spec accessor and mutator that benefits from a cache lives here.
///
/// # Invariants
///
/// The pubkey cache mirrors a prefix of the registry.
/// Cached committees belong to epochs whose active set and seed are already fixed.
#[derive(Clone, Debug)]
pub struct State<P: Preset> {
    /// The consensus state.
    pub(crate) beacon: BeaconState<P>,
    /// Decompressed keys and the key-to-index map.
    pub(crate) pubkeys: PubkeyCache,
    /// Committees of the previous, current, and next epochs, computed on demand.
    pub(crate) committees: Vec<Arc<EpochCommittees>>,
}

impl<P: Preset> State<P> {
    /// Wraps a beacon state, with empty caches.
    #[must_use]
    pub fn new(beacon: BeaconState<P>) -> Self {
        let mut pubkeys = PubkeyCache::default();
        pubkeys.sync(&beacon.validators);
        Self {
            beacon,
            pubkeys,
            committees: Vec::new(),
        }
    }

    /// Wraps a beacon state, reusing a pubkey cache built for an ancestor of it.
    #[must_use]
    pub fn with_pubkeys(beacon: BeaconState<P>, mut pubkeys: PubkeyCache) -> Self {
        pubkeys.sync(&beacon.validators);
        Self {
            beacon,
            pubkeys,
            committees: Vec::new(),
        }
    }

    /// The consensus state.
    #[must_use]
    pub const fn beacon(&self) -> &BeaconState<P> {
        &self.beacon
    }

    /// The consensus state, for direct edits.
    ///
    /// Edits that reorder or replace validators invalidate the caches.
    /// Only spec tests and fork upgrades need this.
    pub fn beacon_mut(&mut self) -> &mut BeaconState<P> {
        // Direct edits may change active sets, so committees are recomputed on demand.
        self.committees.clear();
        &mut self.beacon
    }

    /// The consensus state, without its caches.
    #[must_use]
    pub fn into_beacon(self) -> BeaconState<P> {
        self.beacon
    }

    /// The pubkey cache, to seed the state of a descendant block.
    #[must_use]
    pub const fn pubkeys(&self) -> &PubkeyCache {
        &self.pubkeys
    }

    /// Root of the consensus state.
    #[must_use]
    pub fn hash_tree_root(&self) -> Root {
        self.beacon.hash_tree_root()
    }

    /// Advances through empty slots up to a target slot, running epoch transitions on the way.
    ///
    /// See `process_slots` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the target is not after the state's slot, or an epoch transition fails.
    pub fn process_slots(&mut self, config: &ChainConfig, target: Slot) -> Result<(), StateError> {
        if target <= self.beacon.slot {
            return Err(StateError::SlotNotInFuture {
                target,
                state_slot: self.beacon.slot,
            });
        }
        while self.beacon.slot < target {
            self.process_slot();
            // Timing: the epoch transition runs at the end of an epoch's last slot.
            if (self.beacon.slot.0 + 1).is_multiple_of(P::SLOTS_PER_EPOCH) {
                EpochProcessor::new(self, config).process()?;
            }
            self.beacon.slot += 1;
            self.prune_committees();
        }
        Ok(())
    }

    /// Applies a signed block: empty slots, the proposer signature, the block, the state root.
    ///
    /// See `state_transition` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the block is invalid or its state root does not match.
    pub fn state_transition(
        &mut self,
        config: &ChainConfig,
        signed_block: &SignedBeaconBlock<P>,
        verification: Verification,
        engine: &impl ExecutionEngine<P>,
    ) -> Result<(), TransitionError> {
        let block = &signed_block.message;
        if block.slot > self.beacon.slot {
            self.process_slots(config, block.slot)
                .map_err(TransitionError::Slots)?;
        }

        let mut processor = BlockProcessor::new(self, config, verification);
        processor
            .verify_block_signature(signed_block)
            .map_err(TransitionError::Block)?;
        processor
            .process_block(block, engine)
            .map_err(TransitionError::Block)?;
        processor.finish().map_err(TransitionError::Block)?;

        let computed = self.beacon.hash_tree_root();
        if block.state_root != computed {
            return Err(TransitionError::StateRootMismatch {
                claimed: block.state_root,
                computed,
            });
        }
        Ok(())
    }

    /// Caches the roots of the slot that just ended.
    ///
    /// The latest header's state root is left empty while its block is processed.
    /// It is filled here, one slot later, once the post-state is known.
    ///
    /// See `process_slot` in the phase0 beacon chain spec.
    fn process_slot(&mut self) {
        let index = (self.beacon.slot % P::SLOTS_PER_HISTORICAL_ROOT) as usize;
        let previous_state_root = self.beacon.hash_tree_root();
        self.beacon.state_roots[index] = previous_state_root;
        if self.beacon.latest_block_header.state_root == Root::ZERO {
            self.beacon.latest_block_header.state_root = previous_state_root;
        }
        self.beacon.block_roots[index] = self.beacon.latest_block_header.hash_tree_root();
    }

    /// Drops cached committees outside the previous, current, and next epochs.
    fn prune_committees(&mut self) {
        let current = self.beacon.current_epoch();
        self.committees.retain(|committees| {
            let epoch = committees.epoch();
            epoch.0 + 1 >= current.0 && epoch <= current + 1
        });
    }

    /// Checks that an epoch is one whose committees the state can answer for.
    fn check_committee_epoch(&self, epoch: Epoch) -> Result<(), StateError> {
        let current = self.beacon.current_epoch();
        if epoch < self.beacon.previous_epoch() || epoch > current + 1 {
            return Err(StateError::EpochOutOfRange { epoch, current });
        }
        Ok(())
    }
}
