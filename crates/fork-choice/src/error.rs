//! Reasons the fork choice refuses a message.
//!
//! A refused message leaves the store untouched.
//! Some refusals are temporary, such as a block from the future, and the node may retry later.

use axiom_state_transition::{BlockError, StateError, TransitionError};
use axiom_types::{Epoch, Root, Slot};
use thiserror::Error;

/// A message the fork choice store cannot accept.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ForkChoiceError {
    /// The anchor block does not commit to the anchor state.
    #[error("anchor block claims state root {claimed}, anchor state root is {computed}")]
    AnchorMismatch {
        /// The state root the anchor block claims.
        claimed: Root,
        /// Root of the anchor state.
        computed: Root,
    },
    /// The parent of a block is not in the store.
    #[error("parent {parent} of block {root} is unknown")]
    UnknownParent {
        /// The block's root.
        root: Root,
        /// The parent root the block names.
        parent: Root,
    },
    /// A block's slot has not started yet.
    #[error("block at slot {slot} is ahead of current slot {current}")]
    FutureBlock {
        /// The block's slot.
        slot: Slot,
        /// The store's current slot.
        current: Slot,
    },
    /// A block is not after the finalized checkpoint.
    #[error("block at slot {slot} is not after finalized slot {finalized}")]
    BeforeFinalized {
        /// The block's slot.
        slot: Slot,
        /// First slot of the finalized epoch.
        finalized: Slot,
    },
    /// A block does not descend from the finalized checkpoint.
    #[error("block {root} does not descend from finalized block {finalized}")]
    NotDescendantOfFinalized {
        /// The block's root.
        root: Root,
        /// Root of the finalized checkpoint.
        finalized: Root,
    },
    /// A block's data is not available.
    #[error("data of block {0} is not available")]
    DataUnavailable(Root),
    /// A block fails the state transition.
    #[error("block {root} is invalid: {source}")]
    InvalidBlock {
        /// The block's root.
        root: Root,
        /// The rule the block breaks, boxed so the refusals of every other message stay small.
        #[source]
        source: Box<TransitionError>,
    },
    /// An attestation targets neither the current nor the previous epoch.
    #[error("attestation target epoch {target} is not current or previous at epoch {current}")]
    AttestationEpochOutOfRange {
        /// The attestation's target epoch.
        target: Epoch,
        /// The store's current epoch.
        current: Epoch,
    },
    /// An attestation's target epoch is not the epoch of its slot.
    #[error("attestation target epoch {target} is not the epoch of slot {slot}")]
    AttestationTargetSlotMismatch {
        /// The attestation's target epoch.
        target: Epoch,
        /// The attestation's slot.
        slot: Slot,
    },
    /// An attestation names a target block the store does not have.
    #[error("attestation target {0} is unknown")]
    UnknownTarget(Root),
    /// An attestation names a head block the store does not have.
    #[error("attestation head {0} is unknown")]
    UnknownHead(Root),
    /// An attestation votes for a block from after the attestation's slot.
    #[error("attestation of slot {slot} votes for a head at later slot {head_slot}")]
    HeadFromFuture {
        /// The attestation's slot.
        slot: Slot,
        /// Slot of the head block it votes for.
        head_slot: Slot,
    },
    /// An attestation's target is not the checkpoint of its head vote.
    #[error("attestation target {target} is not the checkpoint of head {head}")]
    TargetNotHeadCheckpoint {
        /// The target root the attestation names.
        target: Root,
        /// The head root the attestation votes for.
        head: Root,
    },
    /// An attestation's slot has not passed yet.
    #[error("attestation slot {slot} has not passed at slot {current}")]
    AttestationFromFuture {
        /// The attestation's slot.
        slot: Slot,
        /// The store's current slot.
        current: Slot,
    },
    /// An attestation or slashing does not verify against its state.
    #[error("invalid attestation: {0}")]
    InvalidAttestation(#[source] BlockError),
    /// An attester slashing's votes are not slashable.
    #[error("votes with targets {first_target} and {second_target} are not slashable")]
    NotSlashable {
        /// Target epoch of the first vote.
        first_target: Epoch,
        /// Target epoch of the second vote.
        second_target: Epoch,
    },
    /// The store lacks the post-state of a block it holds.
    #[error("post-state of block {0} is missing")]
    MissingState(Root),
    /// The proposer head was asked for while the head still holds the boost.
    #[error("head {0} still holds the proposer boost")]
    HeadStillBoosted(Root),
    /// A state invariant broke.
    #[error("state invariant broke: {0}")]
    State(#[from] StateError),
}
