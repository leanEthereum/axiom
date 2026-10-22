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
    #[error("anchor block does not commit to the anchor state")]
    AnchorMismatch,
    /// The parent of a block is not in the store.
    #[error("parent {0} is unknown")]
    UnknownParent(Root),
    /// A block's slot has not started yet.
    #[error("block at slot {slot} is ahead of current slot {current}")]
    FutureBlock {
        /// The block's slot.
        slot: Slot,
        /// The store's current slot.
        current: Slot,
    },
    /// A block is not after the finalized checkpoint.
    #[error("block at slot {0} is not after finality")]
    BeforeFinalized(Slot),
    /// A block does not descend from the finalized checkpoint.
    #[error("block does not descend from finality")]
    NotDescendantOfFinalized,
    /// A block's data is not available.
    #[error("block data is not available")]
    DataUnavailable,
    /// A block fails the state transition.
    #[error("invalid block: {0}")]
    InvalidBlock(#[source] TransitionError),
    /// An attestation targets neither the current nor the previous epoch.
    #[error("attestation target epoch {0} is not current or previous")]
    AttestationEpochOutOfRange(Epoch),
    /// An attestation's target epoch is not the epoch of its slot.
    #[error("attestation target epoch is not the epoch of its slot")]
    AttestationTargetSlotMismatch,
    /// An attestation names a target block the store does not have.
    #[error("attestation target {0} is unknown")]
    UnknownTarget(Root),
    /// An attestation names a head block the store does not have.
    #[error("attestation head {0} is unknown")]
    UnknownHead(Root),
    /// An attestation votes for a block from after the attestation's slot.
    #[error("attestation votes for a later block")]
    HeadFromFuture,
    /// An attestation's target is not the checkpoint of its head vote.
    #[error("attestation target is not the checkpoint of its head")]
    TargetNotHeadCheckpoint,
    /// An attestation's slot has not passed yet.
    #[error("attestation slot {0} has not passed")]
    AttestationFromFuture(Slot),
    /// An attestation or slashing does not verify against its state.
    #[error("invalid attestation: {0}")]
    InvalidAttestation(#[source] BlockError),
    /// An attester slashing's votes are not slashable.
    #[error("attester slashing votes are not slashable")]
    NotSlashable,
    /// The store lacks the post-state of a block it holds.
    #[error("post-state of block {0} is missing")]
    MissingState(Root),
    /// The proposer head was asked for while the head still holds the boost.
    #[error("head still holds the proposer boost")]
    HeadStillBoosted,
    /// A state invariant broke.
    #[error("state invariant broke: {0}")]
    State(#[from] StateError),
}
