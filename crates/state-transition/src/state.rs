//! A beacon state of any fork, paired with the caches that make processing fast.

use std::{collections::BTreeSet, mem, sync::Arc};

use axiom_bls::PublicKey;
use axiom_types::{
    BlsPubkey, BlsSignature, ChainConfig, CommitteeIndex, Epoch, ForkName, Gwei, Preset, Root,
    Slot, ValidatorIndex, accessors::CoreState, altair, bellatrix, capella, combined, deneb,
    electra, fulu, gloas, phase0,
};

use crate::{
    BlockError, BlockProcessor, CachedState, Caches, EpochCommittees, EpochProcessor, EpochStep,
    Fork, PayloadEngine, PubkeyCache, StateError, TransitionError, Upgrade, Verification,
};

/// A beacon state of whichever fork it belongs to, with its derived caches.
///
/// # Overview
///
/// The state is the consensus object, defined field by field by its fork's spec.
/// The caches are derived from it, and never change its meaning or its root.
///
/// The caches do not depend on the fork, so they live beside the state, not inside it.
/// They survive fork upgrades unchanged.
///
/// # Algorithm
///
/// Every operation that depends on the fork dispatches once, here.
///
/// 1. Match the state's fork.
/// 2. Borrow the concrete state with the caches.
/// 3. Run the fork's rules on that one type, with no further fork checks.
///
/// Slot processing runs one fork's slots up to the next fork boundary.
/// At the boundary it upgrades the state, then continues with the next fork's rules.
///
/// # Performance
///
/// The hot path is monomorphic: block and epoch processing see one concrete state type.
/// An upgrade moves the old state's fields into the new one without copying them.
/// Moving the state out of the enum leaves a default phase0 state in its place for that instant.
#[derive(Clone, Debug)]
pub struct State<P: Preset> {
    /// The consensus state.
    pub(crate) beacon: combined::BeaconState<P>,
    /// The caches derived from it.
    pub(crate) caches: Caches,
}

impl<P: Preset> State<P> {
    /// Wraps a beacon state, with empty caches.
    #[must_use]
    pub fn new(beacon: impl Into<combined::BeaconState<P>>) -> Self {
        Self::with_pubkeys(beacon, PubkeyCache::default())
    }

    /// Wraps a beacon state, reusing a pubkey cache built for an ancestor of it.
    #[must_use]
    pub fn with_pubkeys(beacon: impl Into<combined::BeaconState<P>>, pubkeys: PubkeyCache) -> Self {
        let beacon = beacon.into();
        let caches = Caches::new(&beacon, pubkeys);
        Self { beacon, caches }
    }

    /// Sets whether later transitions check signatures.
    ///
    /// Skipping also accepts every deposit proof of possession, as the spec's tests expect.
    pub const fn set_verification(&mut self, verification: Verification) {
        self.caches.verification = verification;
    }

    /// Whether transitions check signatures.
    #[must_use]
    pub const fn verification(&self) -> Verification {
        self.caches.verification
    }

    /// The fork the state belongs to.
    #[must_use]
    pub fn fork_name(&self) -> ForkName {
        self.beacon.fork_name()
    }

    /// The consensus state.
    #[must_use]
    pub const fn beacon(&self) -> &combined::BeaconState<P> {
        &self.beacon
    }

    /// The consensus state, for direct edits.
    ///
    /// Edits that reorder or replace validators invalidate the caches.
    /// Only spec tests and fork upgrades need this.
    pub fn beacon_mut(&mut self) -> &mut combined::BeaconState<P> {
        // Direct edits may change active sets, so committees and proposers are recomputed on demand.
        self.caches.invalidate();
        &mut self.beacon
    }

    /// The consensus state, without its caches.
    #[must_use]
    pub fn into_beacon(self) -> combined::BeaconState<P> {
        self.beacon
    }

    /// The pubkey cache, to seed the state of a descendant block.
    #[must_use]
    pub const fn pubkeys(&self) -> &PubkeyCache {
        self.caches.pubkeys()
    }

    /// Root of the consensus state.
    #[must_use]
    pub fn hash_tree_root(&self) -> Root {
        self.beacon.hash_tree_root()
    }

    /// The concrete state of one fork, with the caches, when the state is of that fork.
    ///
    /// Per-fork code and spec tests reach the fork's rules through it.
    pub fn of_fork<S: Fork<Preset = P>>(&mut self) -> Option<CachedState<'_, S>> {
        let beacon = S::from_any_mut(&mut self.beacon)?;
        Some(CachedState::new(beacon, &mut self.caches))
    }

    /// The state as the core every fork shares, with the caches.
    pub const fn any_fork(&mut self) -> CachedState<'_, combined::BeaconState<P>> {
        CachedState::new(&mut self.beacon, &mut self.caches)
    }

    /// Advances through empty slots up to a target slot.
    ///
    /// Epoch transitions run at each epoch's last slot.
    /// The state upgrades at the first slot of each fork's epoch.
    /// See `process_slots` in the phase0 beacon chain spec, and each fork's fork spec.
    ///
    /// # Errors
    ///
    /// Fails when the target is not after the state's slot, or a transition fails.
    pub fn process_slots(&mut self, config: &ChainConfig, target: Slot) -> Result<(), StateError> {
        let state_slot = self.beacon.slot();
        if target <= state_slot {
            return Err(StateError::SlotNotInFuture { target, state_slot });
        }
        while self.beacon.slot() < target {
            // Phase 1: the current fork's slots, up to the target or the next fork boundary.
            let until = self
                .next_boundary(config)
                .map_or(target, |boundary| boundary.min(target));
            self.dispatch_mut(AdvanceSlots { config, until })?;

            // Phase 2: every upgrade due at the slot reached, in fork order.
            while self.is_upgrade_due(config) {
                self.upgrade(config)?;
            }
        }
        Ok(())
    }

    /// Upgrades the state to the next fork, whatever its slot.
    ///
    /// Slot processing calls this at fork boundaries; spec tests call it directly.
    ///
    /// # Errors
    ///
    /// Fails for a state of the last fork, or when the upgrade cannot derive a value.
    /// A failed upgrade leaves a placeholder state, which the caller discards.
    pub fn upgrade(&mut self, config: &ChainConfig) -> Result<(), StateError> {
        let fork = self.fork_name();
        if fork.next().is_none() {
            return Err(StateError::NoNextFork(fork));
        }
        let caches = &mut self.caches;
        let placeholder = combined::BeaconState::Phase0(phase0::BeaconState::default());
        self.beacon = match mem::replace(&mut self.beacon, placeholder) {
            combined::BeaconState::Phase0(pre) => {
                altair::BeaconState::upgrade(pre, caches, config)?.into()
            }
            combined::BeaconState::Altair(pre) => {
                bellatrix::BeaconState::upgrade(pre, caches, config)?.into()
            }
            combined::BeaconState::Bellatrix(pre) => {
                capella::BeaconState::upgrade(pre, caches, config)?.into()
            }
            combined::BeaconState::Capella(pre) => {
                deneb::BeaconState::upgrade(pre, caches, config)?.into()
            }
            combined::BeaconState::Deneb(pre) => {
                electra::BeaconState::upgrade(pre, caches, config)?.into()
            }
            combined::BeaconState::Electra(pre) => {
                fulu::BeaconState::upgrade(pre, caches, config)?.into()
            }
            combined::BeaconState::Fulu(pre) => {
                gloas::BeaconState::upgrade(pre, caches, config)?.into()
            }
            // Invariant: a state of the last fork returned early, so this arm puts it back unchanged.
            combined::BeaconState::Gloas(pre) => pre.into(),
        };
        Ok(())
    }

    /// Applies a signed block: empty slots, the proposer signature, the block, the state root.
    ///
    /// The block may be of a known fork or of any fork.
    /// After the empty slots, the state must be of the block's fork.
    /// See `state_transition` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the block is of another fork, is invalid, or its state root does not match.
    pub fn state_transition<B: SignedBlock<P>, E: PayloadEngine<P>>(
        &mut self,
        config: &ChainConfig,
        signed_block: &B,
        verification: Verification,
        engine: &E,
    ) -> Result<(), TransitionError> {
        self.caches.verification = verification;
        let slot = signed_block.slot();
        if slot > self.beacon.slot() {
            self.process_slots(config, slot)
                .map_err(|source| TransitionError::Slots {
                    target: slot,
                    source,
                })?;
        }
        signed_block.apply_to(self, config, engine)
    }

    /// Applies a signed block of one fork to a state already at its slot.
    ///
    /// # Errors
    ///
    /// Fails when the state is of another fork, the block is invalid, or the root differs.
    pub fn apply_block<S: Fork<Preset = P>, E: PayloadEngine<P>>(
        &mut self,
        config: &ChainConfig,
        block: &S::Block,
        signature: &BlsSignature,
        engine: &E,
    ) -> Result<(), TransitionError> {
        let header = S::block_header(block);
        let verification = self.caches.verification;
        let state_fork = self.fork_name();
        let state = self.of_fork::<S>().ok_or(TransitionError::ForkMismatch {
            slot: header.slot,
            block: S::FORK,
            state: state_fork,
        })?;
        let invalid = |source| TransitionError::Block {
            slot: header.slot,
            source,
        };
        let mut processor = BlockProcessor::new(state, config, verification);
        processor
            .verify_block_signature(&header, signature)
            .map_err(invalid)?;
        S::process_block(&mut processor, block, &header, engine).map_err(invalid)?;
        processor.finish().map_err(invalid)?;

        let computed = self.beacon.hash_tree_root();
        if header.state_root != computed {
            return Err(TransitionError::StateRootMismatch {
                claimed: header.state_root,
                computed,
            });
        }
        Ok(())
    }

    /// Runs one epoch processing step, by the rules of the state's fork.
    ///
    /// The fork choice runs justification alone to find a block's unrealized checkpoints.
    ///
    /// # Errors
    ///
    /// Fails when the fork does not run the step, or the state breaks an invariant.
    pub fn process_epoch_step(
        &mut self,
        config: &ChainConfig,
        step: EpochStep,
    ) -> Result<(), StateError> {
        self.dispatch_mut(RunEpochStep { config, step })
    }

    /// Proposer of the state's slot, by the rules of the state's fork.
    ///
    /// # Errors
    ///
    /// Fails when the slot's epoch has no active validator.
    pub fn beacon_proposer_index(&self) -> Result<ValidatorIndex, StateError> {
        self.dispatch(ProposerIndex)
    }

    /// Committees of the previous, current, or next epoch.
    ///
    /// # Errors
    ///
    /// Fails for any other epoch, whose committees are not fixed yet or no longer kept.
    pub fn committees(&mut self, epoch: Epoch) -> Result<Arc<EpochCommittees>, StateError> {
        self.any_fork().committees(epoch)
    }

    /// Committees of any epoch whose randomness the state holds, cached ones reused.
    ///
    /// Epochs outside the cached window are computed afresh and not kept.
    #[must_use]
    pub fn compute_committees(&mut self, epoch: Epoch) -> Arc<EpochCommittees> {
        self.any_fork().compute_committees(epoch)
    }

    /// Validators an Electra attestation counts, sorted and unique.
    ///
    /// See `get_attesting_indices` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the target epoch's committees are not kept, or the bits do not fit them.
    pub fn attesting_indices(
        &mut self,
        attestation: &electra::Attestation<P>,
    ) -> Result<BTreeSet<ValidatorIndex>, BlockError> {
        let data = &attestation.data;
        self.committees(data.target.epoch)?.attesters(
            data.slot,
            attestation.committee_indices(),
            attestation.aggregation_bits.iter(),
        )
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
        self.any_fork().beacon_committee(slot, index)
    }

    /// Decompressed key of a validator.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist or its key does not decompress.
    pub fn public_key(&mut self, index: ValidatorIndex) -> Result<PublicKey, StateError> {
        self.any_fork().public_key(index)
    }

    /// Index of the validator with a key.
    pub fn validator_index(&mut self, pubkey: &BlsPubkey) -> Option<ValidatorIndex> {
        self.any_fork().validator_index(pubkey)
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
        self.any_fork().increase_balance(index, delta)
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
        self.any_fork().decrease_balance(index, delta)
    }

    /// First slot of the next fork's epoch, when that fork is scheduled after the state's slot.
    fn next_boundary(&self, config: &ChainConfig) -> Option<Slot> {
        let next = self.fork_name().next()?;
        // A fork scheduled at the far future epoch has no first slot.
        let boundary = config
            .fork_epoch(next)
            .0
            .checked_mul(P::SLOTS_PER_EPOCH)
            .map(Slot)?;
        (boundary > self.beacon.slot()).then_some(boundary)
    }

    /// Whether the state sits at the first slot of the next fork's epoch.
    fn is_upgrade_due(&self, config: &ChainConfig) -> bool {
        let slot = self.beacon.slot();
        self.fork_name().next().is_some_and(|next| {
            slot.is_epoch_start::<P>() && config.fork_epoch(next) == slot.epoch::<P>()
        })
    }

    /// Runs a task on the state's concrete type, with the caches.
    fn dispatch_mut<T: ForkTaskMut<P>>(&mut self, task: T) -> T::Output {
        let caches = &mut self.caches;
        match &mut self.beacon {
            combined::BeaconState::Phase0(state) => task.run(CachedState::new(state, caches)),
            combined::BeaconState::Altair(state) => task.run(CachedState::new(state, caches)),
            combined::BeaconState::Bellatrix(state) => task.run(CachedState::new(state, caches)),
            combined::BeaconState::Capella(state) => task.run(CachedState::new(state, caches)),
            combined::BeaconState::Deneb(state) => task.run(CachedState::new(state, caches)),
            combined::BeaconState::Electra(state) => task.run(CachedState::new(state, caches)),
            combined::BeaconState::Fulu(state) => task.run(CachedState::new(state, caches)),
            combined::BeaconState::Gloas(state) => task.run(CachedState::new(state, caches)),
        }
    }

    /// Runs a read-only task on the state's concrete type.
    fn dispatch<T: ForkTask<P>>(&self, task: T) -> T::Output {
        match &self.beacon {
            combined::BeaconState::Phase0(state) => task.run(state),
            combined::BeaconState::Altair(state) => task.run(state),
            combined::BeaconState::Bellatrix(state) => task.run(state),
            combined::BeaconState::Capella(state) => task.run(state),
            combined::BeaconState::Deneb(state) => task.run(state),
            combined::BeaconState::Electra(state) => task.run(state),
            combined::BeaconState::Fulu(state) => task.run(state),
            combined::BeaconState::Gloas(state) => task.run(state),
        }
    }
}

/// A signed block that a state can apply: one fork's, or any fork's.
///
/// Fulu kept Electra's block type, so an Electra block applies to an Electra or a Fulu state.
pub trait SignedBlock<P: Preset> {
    /// Slot the block is proposed in.
    fn slot(&self) -> Slot;

    /// Applies the block to a state already advanced to its slot.
    ///
    /// # Errors
    ///
    /// Fails when the state's fork does not apply this block, or the block is invalid.
    fn apply_to<E: PayloadEngine<P>>(
        &self,
        state: &mut State<P>,
        config: &ChainConfig,
        engine: &E,
    ) -> Result<(), TransitionError>;
}

impl<P: Preset> SignedBlock<P> for phase0::SignedBeaconBlock<P> {
    fn slot(&self) -> Slot {
        self.message.slot
    }

    fn apply_to<E: PayloadEngine<P>>(
        &self,
        state: &mut State<P>,
        config: &ChainConfig,
        engine: &E,
    ) -> Result<(), TransitionError> {
        state.apply_block::<phase0::BeaconState<P>, E>(
            config,
            &self.message,
            &self.signature,
            engine,
        )
    }
}

impl<P: Preset> SignedBlock<P> for altair::SignedBeaconBlock<P> {
    fn slot(&self) -> Slot {
        self.message.slot
    }

    fn apply_to<E: PayloadEngine<P>>(
        &self,
        state: &mut State<P>,
        config: &ChainConfig,
        engine: &E,
    ) -> Result<(), TransitionError> {
        state.apply_block::<altair::BeaconState<P>, E>(
            config,
            &self.message,
            &self.signature,
            engine,
        )
    }
}

impl<P: Preset> SignedBlock<P> for bellatrix::SignedBeaconBlock<P> {
    fn slot(&self) -> Slot {
        self.message.slot
    }

    fn apply_to<E: PayloadEngine<P>>(
        &self,
        state: &mut State<P>,
        config: &ChainConfig,
        engine: &E,
    ) -> Result<(), TransitionError> {
        state.apply_block::<bellatrix::BeaconState<P>, E>(
            config,
            &self.message,
            &self.signature,
            engine,
        )
    }
}

impl<P: Preset> SignedBlock<P> for capella::SignedBeaconBlock<P> {
    fn slot(&self) -> Slot {
        self.message.slot
    }

    fn apply_to<E: PayloadEngine<P>>(
        &self,
        state: &mut State<P>,
        config: &ChainConfig,
        engine: &E,
    ) -> Result<(), TransitionError> {
        state.apply_block::<capella::BeaconState<P>, E>(
            config,
            &self.message,
            &self.signature,
            engine,
        )
    }
}

impl<P: Preset> SignedBlock<P> for deneb::SignedBeaconBlock<P> {
    fn slot(&self) -> Slot {
        self.message.slot
    }

    fn apply_to<E: PayloadEngine<P>>(
        &self,
        state: &mut State<P>,
        config: &ChainConfig,
        engine: &E,
    ) -> Result<(), TransitionError> {
        state.apply_block::<deneb::BeaconState<P>, E>(
            config,
            &self.message,
            &self.signature,
            engine,
        )
    }
}

impl<P: Preset> SignedBlock<P> for electra::SignedBeaconBlock<P> {
    fn slot(&self) -> Slot {
        self.message.slot
    }

    fn apply_to<E: PayloadEngine<P>>(
        &self,
        state: &mut State<P>,
        config: &ChainConfig,
        engine: &E,
    ) -> Result<(), TransitionError> {
        // Fulu kept Electra's block, so the state's fork picks the rules.
        if state.fork_name() == ForkName::Fulu {
            state.apply_block::<fulu::BeaconState<P>, E>(
                config,
                &self.message,
                &self.signature,
                engine,
            )
        } else {
            state.apply_block::<electra::BeaconState<P>, E>(
                config,
                &self.message,
                &self.signature,
                engine,
            )
        }
    }
}

impl<P: Preset> SignedBlock<P> for gloas::SignedBeaconBlock<P> {
    fn slot(&self) -> Slot {
        self.message.slot
    }

    fn apply_to<E: PayloadEngine<P>>(
        &self,
        state: &mut State<P>,
        config: &ChainConfig,
        engine: &E,
    ) -> Result<(), TransitionError> {
        state.apply_block::<gloas::BeaconState<P>, E>(
            config,
            &self.message,
            &self.signature,
            engine,
        )
    }
}

impl<P: Preset> SignedBlock<P> for combined::SignedBeaconBlock<P> {
    fn slot(&self) -> Slot {
        Self::slot(self)
    }

    fn apply_to<E: PayloadEngine<P>>(
        &self,
        state: &mut State<P>,
        config: &ChainConfig,
        engine: &E,
    ) -> Result<(), TransitionError> {
        match self {
            Self::Phase0(block) => block.apply_to(state, config, engine),
            Self::Altair(block) => block.apply_to(state, config, engine),
            Self::Bellatrix(block) => block.apply_to(state, config, engine),
            Self::Capella(block) => block.apply_to(state, config, engine),
            Self::Deneb(block) => block.apply_to(state, config, engine),
            Self::Electra(block) => state.apply_block::<electra::BeaconState<P>, E>(
                config,
                &block.message,
                &block.signature,
                engine,
            ),
            Self::Fulu(block) => state.apply_block::<fulu::BeaconState<P>, E>(
                config,
                &block.message,
                &block.signature,
                engine,
            ),
            Self::Gloas(block) => block.apply_to(state, config, engine),
        }
    }
}

/// Code generic over the fork, run once on the state's concrete type with the caches.
///
/// Closures cannot be generic over a type, so each such task is a small type of its own.
trait ForkTaskMut<P: Preset> {
    /// What the task returns.
    type Output;

    /// Runs the task on one fork's state.
    fn run<S: Fork<Preset = P>>(self, state: CachedState<'_, S>) -> Self::Output;
}

/// Read-only code generic over the fork, run once on the state's concrete type.
trait ForkTask<P: Preset> {
    /// What the task returns.
    type Output;

    /// Runs the task on one fork's state.
    fn run<S: Fork<Preset = P>>(self, state: &S) -> Self::Output;
}

/// Slot processing within one fork, up to a slot no later than the fork's last.
#[derive(Clone, Copy, Debug)]
struct AdvanceSlots<'a> {
    /// The chain configuration.
    config: &'a ChainConfig,
    /// The slot to stop at.
    until: Slot,
}

impl<P: Preset> ForkTaskMut<P> for AdvanceSlots<'_> {
    type Output = Result<(), StateError>;

    fn run<S: Fork<Preset = P>>(self, mut state: CachedState<'_, S>) -> Self::Output {
        while state.beacon.slot() < self.until {
            S::process_slot(state.beacon);
            // Timing: the epoch transition runs at the end of an epoch's last slot.
            if (state.beacon.slot().0 + 1).is_multiple_of(P::SLOTS_PER_EPOCH) {
                EpochProcessor::new(state.reborrow(), self.config).process()?;
            }
            *state.beacon.slot_mut() += 1;
            let current = state.beacon.current_epoch();
            state.caches.prune_committees(current);
        }
        Ok(())
    }
}

/// One epoch step, outside a full epoch transition.
#[derive(Clone, Copy, Debug)]
struct RunEpochStep<'a> {
    /// The chain configuration.
    config: &'a ChainConfig,
    /// The step to run.
    step: EpochStep,
}

impl<P: Preset> ForkTaskMut<P> for RunEpochStep<'_> {
    type Output = Result<(), StateError>;

    fn run<S: Fork<Preset = P>>(self, state: CachedState<'_, S>) -> Self::Output {
        EpochProcessor::new(state, self.config).run(self.step)
    }
}

/// The proposer of the state's slot.
#[derive(Clone, Copy, Debug)]
struct ProposerIndex;

impl<P: Preset> ForkTask<P> for ProposerIndex {
    type Output = Result<ValidatorIndex, StateError>;

    fn run<S: Fork<Preset = P>>(self, state: &S) -> Self::Output {
        S::beacon_proposer_index(state)
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;

    use super::*;
    use crate::KnownVerdict;

    #[test]
    fn a_block_of_another_fork_is_refused() {
        // Fixture state: a default Fulu state at slot 0, and a default phase0 block for slot 0.
        let mut state = State::new(fulu::BeaconState::<Minimal>::default());
        let block = phase0::SignedBeaconBlock::<Minimal>::default();

        let outcome = state.state_transition(
            &ChainConfig::minimal(),
            &block,
            Verification::Skip,
            &KnownVerdict(true),
        );

        assert_eq!(
            outcome,
            Err(TransitionError::ForkMismatch {
                slot: Slot(0),
                block: ForkName::Phase0,
                state: ForkName::Fulu,
            })
        );
    }

    #[test]
    fn the_last_fork_has_nothing_to_upgrade_to() {
        // Fixture state: a default Gloas state, which no fork follows.
        let mut state = State::new(gloas::BeaconState::<Minimal>::default());

        let outcome = state.upgrade(&ChainConfig::minimal());

        assert_eq!(outcome, Err(StateError::NoNextFork(ForkName::Gloas)));
        assert_eq!(state.fork_name(), ForkName::Gloas);
    }
}
