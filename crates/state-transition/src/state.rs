//! A beacon state paired with the caches that make processing fast.

use std::{collections::BTreeSet, sync::Arc};

use axiom_bls::PublicKey;
use axiom_ssz::Ssz;
use axiom_types::{
    Attestation, BeaconState, BlsPubkey, ChainConfig, CommitteeIndex, Epoch, Gwei, Preset, Root,
    SignedBeaconBlock, Slot, ValidatorIndex, electra,
};

use crate::{
    BlockError, BlockProcessor, EpochCommittees, EpochProcessor, ExecutionEngine, PubkeyCache,
    StateError, TransitionError, Verification, sampling::WeightedSampler,
};

/// A beacon state with its derived caches.
///
/// # Overview
///
/// The beacon state is the consensus object, defined field by field by the spec.
/// The caches are derived from it, and never change its meaning or its root.
///
/// The accessors that benefit from a cache live here.
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
    /// Whether signatures are checked, including deposit proofs of possession in epoch processing.
    pub(crate) verification: Verification,
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
            verification: Verification::Verify,
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
            verification: Verification::Verify,
        }
    }

    /// Upgrades an Electra state to Fulu, at the first slot of the fork epoch.
    ///
    /// Every field carries over, and the fork version advances.
    /// The new proposer lookahead is computed from the upgraded state itself.
    ///
    /// See `upgrade_to_fulu` and `initialize_proposer_lookahead` in the Fulu fork spec.
    ///
    /// # Errors
    ///
    /// Fails when an epoch of the lookahead has no active validator.
    pub fn upgrade_from_electra(
        pre: electra::BeaconState<P>,
        config: &ChainConfig,
    ) -> Result<Self, StateError> {
        let mut state = Self::new(pre.upgrade_to_fulu(config.fulu_fork_version));
        let epoch = state.beacon.current_epoch();
        // The lookahead spans the current epoch and the next MIN_SEED_LOOKAHEAD epochs.
        let mut lookahead = Vec::with_capacity(state.beacon.proposer_lookahead.len());
        for offset in 0..=P::MIN_SEED_LOOKAHEAD {
            lookahead.extend(WeightedSampler::proposers(&state.beacon, epoch + offset)?);
        }
        state.beacon.proposer_lookahead =
            lookahead
                .try_into()
                .map_err(|source| StateError::Capacity {
                    list: "proposer lookahead",
                    source,
                })?;
        Ok(state)
    }

    /// Sets whether later transitions check signatures.
    ///
    /// Skipping also accepts every deposit proof of possession, as the spec's tests expect.
    pub const fn set_verification(&mut self, verification: Verification) {
        self.verification = verification;
    }

    /// Whether transitions check signatures.
    #[must_use]
    pub const fn verification(&self) -> Verification {
        self.verification
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
        self.verification = verification;
        let block = &signed_block.message;
        if block.slot > self.beacon.slot {
            self.process_slots(config, block.slot)
                .map_err(|source| TransitionError::Slots {
                    target: block.slot,
                    source,
                })?;
        }

        let invalid = |source| TransitionError::Block {
            slot: block.slot,
            source,
        };
        let mut processor = BlockProcessor::new(self, config, verification);
        processor
            .verify_block_signature(signed_block)
            .map_err(invalid)?;
        processor.process_block(block, engine).map_err(invalid)?;
        processor.finish().map_err(invalid)?;

        let computed = self.beacon.hash_tree_root();
        if block.state_root != computed {
            return Err(TransitionError::StateRootMismatch {
                claimed: block.state_root,
                computed,
            });
        }
        Ok(())
    }

    /// Committees of the previous, current, or next epoch.
    ///
    /// # Errors
    ///
    /// Fails for any other epoch, whose committees are not fixed yet or no longer kept.
    pub fn committees(&mut self, epoch: Epoch) -> Result<Arc<EpochCommittees>, StateError> {
        self.check_committee_epoch(epoch)?;
        if let Some(found) = self
            .committees
            .iter()
            .find(|cached| cached.epoch() == epoch)
        {
            return Ok(Arc::clone(found));
        }
        let computed = Arc::new(EpochCommittees::compute(&self.beacon, epoch));
        self.committees.push(Arc::clone(&computed));
        Ok(computed)
    }

    /// Committees of any epoch whose randomness the state holds, cached ones reused.
    ///
    /// Epochs outside the cached window are computed afresh and not kept.
    #[must_use]
    pub fn compute_committees(&mut self, epoch: Epoch) -> Arc<EpochCommittees> {
        self.committees(epoch)
            .unwrap_or_else(|_| Arc::new(EpochCommittees::compute(&self.beacon, epoch)))
    }

    /// Validators an attestation counts, sorted and unique.
    ///
    /// See `get_attesting_indices` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the target epoch's committees are not kept, or the bits do not fit them.
    pub fn attesting_indices(
        &mut self,
        attestation: &Attestation<P>,
    ) -> Result<BTreeSet<ValidatorIndex>, BlockError> {
        self.committees(attestation.data.target.epoch)?
            .attesting_indices(attestation)
    }

    /// The beacon committee at a slot and index.
    ///
    /// # Errors
    ///
    /// Fails when the slot's epoch is not cached or the committee does not exist.
    pub fn beacon_committee(
        &mut self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Result<Vec<ValidatorIndex>, BlockError> {
        let committees = self.committees(slot.epoch::<P>())?;
        committees
            .committee(slot, index)
            .map(<[ValidatorIndex]>::to_vec)
            .ok_or_else(|| BlockError::UnknownCommittee {
                slot,
                index,
                committees_per_slot: committees.committees_per_slot(),
            })
    }

    /// Decompressed key of a validator.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist or its key does not decompress.
    pub fn public_key(&mut self, index: ValidatorIndex) -> Result<PublicKey, StateError> {
        let validators = &self.beacon.validators;
        let validator = validators
            .get(index.as_usize())
            .ok_or(StateError::UnknownValidator {
                index,
                registry_size: validators.len(),
            })?;
        self.pubkeys.sync(validators);
        self.pubkeys
            .public_key(index, &validator.pubkey)
            .ok_or(StateError::MalformedPublicKey(index))
    }

    /// Index of the validator with a key.
    pub fn validator_index(&mut self, pubkey: &BlsPubkey) -> Option<ValidatorIndex> {
        self.pubkeys.sync(&self.beacon.validators);
        self.pubkeys.index_of(pubkey)
    }

    /// Adds to a validator's balance.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist or the balance overflows.
    pub fn increase_balance(
        &mut self,
        index: ValidatorIndex,
        delta: Gwei,
    ) -> Result<(), StateError> {
        let registry_size = self.beacon.balances.len();
        let balance =
            self.beacon
                .balances
                .get_mut(index.as_usize())
                .ok_or(StateError::UnknownValidator {
                    index,
                    registry_size,
                })?;
        *balance = balance.checked_add(delta).ok_or(StateError::Overflow {
            quantity: "balance",
        })?;
        Ok(())
    }

    /// Takes from a validator's balance, stopping at zero.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist.
    pub fn decrease_balance(
        &mut self,
        index: ValidatorIndex,
        delta: Gwei,
    ) -> Result<(), StateError> {
        let registry_size = self.beacon.balances.len();
        let balance =
            self.beacon
                .balances
                .get_mut(index.as_usize())
                .ok_or(StateError::UnknownValidator {
                    index,
                    registry_size,
                })?;
        *balance = balance.saturating_sub(delta);
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
