//! Reasons the fork choice refuses a message.
//!
//! A refused message leaves the store untouched.
//! Some refusals are temporary, such as a block from the future, and the node may retry later.

use std::{error::Error, fmt};

use axiom_state_transition::{BlockError, StateError, TransitionError};
use axiom_types::{Epoch, Root, Slot};

/// A message the fork choice store cannot accept.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForkChoiceError {
    /// The anchor block does not commit to the anchor state.
    AnchorMismatch,
    /// The parent of a block is not in the store.
    UnknownParent(Root),
    /// A block's slot has not started yet.
    FutureBlock {
        /// The block's slot.
        slot: Slot,
        /// The store's current slot.
        current: Slot,
    },
    /// A block is not after the finalized checkpoint.
    BeforeFinalized(Slot),
    /// A block does not descend from the finalized checkpoint.
    NotDescendantOfFinalized,
    /// A block's data is not available.
    DataUnavailable,
    /// A block fails the state transition.
    InvalidBlock(TransitionError),
    /// An attestation targets neither the current nor the previous epoch.
    AttestationEpochOutOfRange(Epoch),
    /// An attestation's target epoch is not the epoch of its slot.
    AttestationTargetSlotMismatch,
    /// An attestation names a target block the store does not have.
    UnknownTarget(Root),
    /// An attestation names a head block the store does not have.
    UnknownHead(Root),
    /// An attestation votes for a block from after the attestation's slot.
    HeadFromFuture,
    /// An attestation's target is not the checkpoint of its head vote.
    TargetNotHeadCheckpoint,
    /// An attestation's slot has not passed yet.
    AttestationFromFuture(Slot),
    /// An attestation or slashing does not verify against its state.
    InvalidAttestation(BlockError),
    /// An attester slashing's votes are not slashable.
    NotSlashable,
    /// The store lacks the post-state of a block it holds.
    MissingState(Root),
    /// The proposer head was asked for while the head still holds the boost.
    HeadStillBoosted,
    /// A state invariant broke.
    State(StateError),
}

impl fmt::Display for ForkChoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnchorMismatch => f.write_str("anchor block does not commit to the anchor state"),
            Self::UnknownParent(root) => write!(f, "parent {root} is unknown"),
            Self::FutureBlock { slot, current } => {
                write!(f, "block at slot {slot} is ahead of current slot {current}")
            }
            Self::BeforeFinalized(slot) => write!(f, "block at slot {slot} is not after finality"),
            Self::NotDescendantOfFinalized => f.write_str("block does not descend from finality"),
            Self::DataUnavailable => f.write_str("block data is not available"),
            Self::InvalidBlock(error) => write!(f, "invalid block: {error}"),
            Self::AttestationEpochOutOfRange(epoch) => {
                write!(
                    f,
                    "attestation target epoch {epoch} is not current or previous"
                )
            }
            Self::AttestationTargetSlotMismatch => {
                f.write_str("attestation target epoch is not the epoch of its slot")
            }
            Self::UnknownTarget(root) => write!(f, "attestation target {root} is unknown"),
            Self::UnknownHead(root) => write!(f, "attestation head {root} is unknown"),
            Self::HeadFromFuture => f.write_str("attestation votes for a later block"),
            Self::TargetNotHeadCheckpoint => {
                f.write_str("attestation target is not the checkpoint of its head")
            }
            Self::AttestationFromFuture(slot) => {
                write!(f, "attestation slot {slot} has not passed")
            }
            Self::InvalidAttestation(error) => write!(f, "invalid attestation: {error}"),
            Self::NotSlashable => f.write_str("attester slashing votes are not slashable"),
            Self::MissingState(root) => write!(f, "post-state of block {root} is missing"),
            Self::HeadStillBoosted => f.write_str("head still holds the proposer boost"),
            Self::State(error) => write!(f, "state invariant broke: {error}"),
        }
    }
}

impl Error for ForkChoiceError {}

impl From<StateError> for ForkChoiceError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}
