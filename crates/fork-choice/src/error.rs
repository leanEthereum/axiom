//! Reasons the fork choice refuses a message.
//!
//! A refused message leaves the store untouched.
//! Some refusals are temporary, such as a block from the future, and the node may retry later.

use axiom_state_transition::{BlockError, StateError, TransitionError, gloas::EnvelopeError};
use axiom_types::{Epoch, Hash32, Root, Slot, ValidatorIndex};
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
    /// A block builds on its parent's payload, which has not been verified.
    #[error("block {root} builds on the payload of {parent}, which is not verified")]
    ParentPayloadUnverified {
        /// The block's root.
        root: Root,
        /// The parent whose payload is missing.
        parent: Root,
    },
    /// A message names a block the store does not have.
    #[error("block {0} is unknown")]
    UnknownBlock(Root),
    /// A payload envelope does not verify against its block's state.
    #[error("payload envelope of block {root} is invalid: {source}")]
    InvalidEnvelope {
        /// The block the envelope reveals the payload of.
        root: Root,
        /// The rule the envelope breaks.
        #[source]
        source: EnvelopeError,
    },
    /// A payload vote names a block from before Gloas, which has no payload committee.
    #[error("block {0} has no payload timeliness committee")]
    NoPayloadCommittee(Root),
    /// A payload vote comes from a validator outside the slot's committee.
    #[error("validator {validator} is not in the payload timeliness committee of slot {slot}")]
    NotInPayloadCommittee {
        /// The voter.
        validator: ValidatorIndex,
        /// The slot voted on.
        slot: Slot,
    },
    /// A payload vote from the wire is not for the current slot.
    #[error("payload vote for slot {slot} arrived at slot {current}")]
    PayloadVoteNotCurrent {
        /// The slot voted on.
        slot: Slot,
        /// The store's current slot.
        current: Slot,
    },
    /// A payload vote's signature does not verify.
    #[error("invalid payload vote: {0}")]
    InvalidPayloadVote(#[source] BlockError),
    /// A Gloas vote's data index is neither zero nor one.
    #[error("vote data index {0} is neither 0 nor 1")]
    PayloadIndexOutOfRange(u64),
    /// A Gloas vote claims a payload in the slot of its own block, before any payload could exist.
    #[error("vote of slot {0} claims the payload of a block from the same slot")]
    SameSlotPayloadClaim(Slot),
    /// A Gloas vote claims a payload the store has not verified.
    #[error("vote claims the payload of block {0}, which is not verified")]
    UnverifiedPayloadClaim(Root),
    /// A merge block arrives before a hand-fixed terminal block may be built on.
    #[error("merge block at epoch {epoch} precedes terminal block activation epoch {activation}")]
    TerminalBlockTooEarly {
        /// The merge block's epoch.
        epoch: Epoch,
        /// The configured activation epoch.
        activation: Epoch,
    },
    /// A merge block's payload does not build on the hand-fixed terminal block.
    #[error("merge payload builds on {parent_hash}, not the terminal block {terminal}")]
    NotTerminalBlockHash {
        /// The payload's parent hash.
        parent_hash: Hash32,
        /// The configured terminal block hash.
        terminal: Hash32,
    },
    /// A proof-of-work block the merge check needs is unknown.
    #[error("proof-of-work block {0} is unknown")]
    UnknownPowBlock(Hash32),
    /// A merge block's payload builds on a block that is not the terminal proof-of-work block.
    #[error("proof-of-work block {0} is not the terminal block")]
    NotTerminalPowBlock(Hash32),
    /// A state invariant broke.
    #[error("state invariant broke: {0}")]
    State(#[from] StateError),
}
