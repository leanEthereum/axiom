//! What each fork's spec defines over its own state, and how one fork's state becomes the next.

use std::fmt::Debug;

use axiom_ssz::Ssz;
use axiom_types::{ChainConfig, ValidatorIndex, accessors::ForkState, phase0::BeaconBlockHeader};

use crate::{
    BlockError, BlockProcessor, CachedState, Caches, EpochProcessor, EpochStep, EpochVotes,
    PayloadEngine, Registry, StateError, rewards::AttesterRewards,
};

/// The state transition rules of one fork, implemented on that fork's state.
///
/// # Overview
///
/// Each fork's folder implements this trait once, on its own state type.
/// The implementation reads as the fork's table of contents.
/// It names its epoch steps and block steps, and which fork's version of each rule it runs.
///
/// Shared code calls a handful of spec functions that later forks rewrote.
/// Those are methods here, so shared code always runs the version of the state's fork.
///
/// Everything below this trait is monomorphic: one concrete state type, no fork checks.
pub trait Fork: ForkState + Ssz + Clone + Debug + 'static {
    /// The unsigned block a state of this fork applies.
    type Block: Ssz;

    /// The epoch processing steps of this fork, in the order its spec runs them.
    ///
    /// See `process_epoch` in the fork's beacon chain spec.
    const EPOCH_STEPS: &'static [EpochStep];

    /// The header of a block, which commits to its body by root.
    ///
    /// A header has the root of its block, so it stands in for the block wherever a root is signed.
    fn block_header(block: &Self::Block) -> BeaconBlockHeader;

    /// Proposer of the state's slot.
    ///
    /// See `get_beacon_proposer_index` in the fork's beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the slot's epoch has no active validator.
    fn beacon_proposer_index(state: &Self) -> Result<ValidatorIndex, StateError>;

    /// Schedules a validator's exit.
    ///
    /// See `initiate_validator_exit` in the fork's beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist or an epoch overflows.
    fn initiate_validator_exit(
        registry: &mut Registry<'_, Self>,
        index: ValidatorIndex,
    ) -> Result<(), StateError>;

    /// Slashes a validator, and pays the proposer and the whistleblower.
    ///
    /// The proposer is the whistleblower when none is given.
    /// See `slash_validator` in the fork's beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when a validator does not exist or a balance overflows.
    fn slash_validator(
        registry: &mut Registry<'_, Self>,
        slashed: ValidatorIndex,
        whistleblower: Option<ValidatorIndex>,
    ) -> Result<(), StateError>;

    /// Caches the roots of the slot that just ended.
    ///
    /// See `process_slot` in the fork's beacon chain spec.
    fn process_slot(state: &mut Self);

    /// Runs one epoch processing step.
    ///
    /// # Errors
    ///
    /// Fails when the step is not one of this fork's, or the state breaks an invariant.
    fn process_epoch_step(
        processor: &mut EpochProcessor<'_, Self>,
        step: EpochStep,
    ) -> Result<(), StateError>;

    /// The attestation rewards of the state's previous epoch, by vote component.
    ///
    /// The state is at the last slot of an epoch, after the epoch steps before the rewards.
    /// See `process_rewards_and_penalties` in the fork's beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the state breaks an invariant.
    fn attester_rewards(
        state: CachedState<'_, Self>,
        config: &ChainConfig,
    ) -> Result<AttesterRewards, StateError>;

    /// Which parts of each validator's vote of the state's previous epoch the state records.
    ///
    /// # Errors
    ///
    /// Fails when a recorded vote names a committee or a root the state does not hold.
    fn previous_epoch_votes(state: CachedState<'_, Self>) -> Result<EpochVotes, StateError>;

    /// Applies a block, given with its header.
    ///
    /// The proposer signature and the state root are checked around this, the same for every fork.
    /// See `process_block` in the fork's beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails at the first broken rule.
    fn process_block<E: PayloadEngine<Self::Preset>>(
        processor: &mut BlockProcessor<'_, Self>,
        block: &Self::Block,
        header: &BeaconBlockHeader,
        engine: &E,
    ) -> Result<(), BlockError>;
}

/// The rules of a fork whose blocks carry an execution payload, applied to blocks whose payload was pruned.
///
/// # Overview
///
/// A blinded block keeps the payload's header, which commits to every payload field.
/// Block processing reads the payload only through that header, but for execution:
///
/// - the parent hash, the randomness, and the timestamp checks read the header,
/// - the withdrawals check compares the expected list's root with the header's,
/// - the state caches the header, which is the payload's header field for field.
///
/// So a blinded block moves the state exactly as its whole block did.
/// Only execution needs the payload, and a pruned payload's block was judged at import.
/// Bellatrix through Fulu have blinded blocks; Gloas moves the payload out of the block.
pub trait BlindedFork: Fork {
    /// The blinded block of this fork.
    type BlindedBlock: Ssz;

    /// The header of a blinded block, the same as its whole block's.
    fn blinded_block_header(block: &Self::BlindedBlock) -> BeaconBlockHeader;

    /// Applies a blinded block, given with its header.
    ///
    /// # Errors
    ///
    /// Fails at the first broken rule.
    fn process_blinded_block(
        processor: &mut BlockProcessor<'_, Self>,
        block: &Self::BlindedBlock,
        header: &BeaconBlockHeader,
    ) -> Result<(), BlockError>;
}

/// A fork's state built from its predecessor's, at the first slot of the fork epoch.
///
/// The pre-state is taken by value: its fields move into the post-state without copies.
pub trait Upgrade: Fork {
    /// The fork this one follows.
    type Previous: Fork<Preset = Self::Preset>;

    /// Upgrades a state of the previous fork.
    ///
    /// See `upgrade_to_<fork>` in the fork's fork spec.
    ///
    /// # Errors
    ///
    /// Fails when a value the upgrade derives cannot be computed, such as a committee of no one.
    fn upgrade(
        pre: Self::Previous,
        caches: &mut Caches,
        config: &ChainConfig,
    ) -> Result<Self, StateError>;
}
