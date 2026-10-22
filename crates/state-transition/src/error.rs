//! Reasons a state transition fails.
//!
//! A block that breaks a rule is invalid, and the node discards it.
//! A state that breaks an invariant is corrupt, which a valid chain never produces.

use axiom_types::{CommitteeIndex, Epoch, Root, Slot, ValidatorIndex};
use thiserror::Error;

/// A state that violates an invariant the protocol relies on.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum StateError {
    /// A validator index points past the registry.
    #[error("validator {0} is not in the registry")]
    UnknownValidator(ValidatorIndex),
    /// A block root was read outside the window the state keeps.
    #[error("block root of slot {slot} is not kept at slot {state_slot}")]
    BlockRootOutOfRange {
        /// The slot asked for.
        slot: Slot,
        /// The state's slot.
        state_slot: Slot,
    },
    /// Committees were asked for an epoch other than the previous, current, or next one.
    #[error("committees of epoch {epoch} are not known at epoch {current}")]
    EpochOutOfRange {
        /// The epoch asked for.
        epoch: Epoch,
        /// The state's epoch.
        current: Epoch,
    },
    /// An epoch has no active validator, so no committee or proposer exists.
    #[error("epoch {0} has no active validator")]
    NoActiveValidators(Epoch),
    /// A balance or counter overflowed 64 bits.
    #[error("arithmetic overflow")]
    Overflow,
    /// A list in the state is at its SSZ limit.
    #[error("a state list is at its limit")]
    ListFull,
    /// Slot processing was asked to go backwards or stand still.
    #[error("target slot {target} is not after state slot {state_slot}")]
    SlotNotInFuture {
        /// The target slot.
        target: Slot,
        /// The state's slot.
        state_slot: Slot,
    },
    /// The next sync committee could not be aggregated.
    #[error("the next sync committee does not aggregate")]
    InvalidSyncCommittee,
}

/// A block that breaks a rule of block processing.
///
/// Each variant names the assertion of the spec that failed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BlockError {
    /// The block's slot is not the state's slot.
    #[error("block slot {block} is not state slot {state}")]
    SlotMismatch {
        /// The block's slot.
        block: Slot,
        /// The state's slot.
        state: Slot,
    },
    /// The block is not newer than the latest block.
    #[error("block is not newer than the latest block")]
    NotNewerThanParent,
    /// The block names the wrong proposer.
    #[error("block names proposer {claimed}, slot proposer is {expected}")]
    WrongProposer {
        /// The proposer the block names.
        claimed: ValidatorIndex,
        /// The proposer of the slot.
        expected: ValidatorIndex,
    },
    /// The block's parent is not the latest block.
    #[error("block parent {claimed} is not the latest block {expected}")]
    ParentMismatch {
        /// The parent the block names.
        claimed: Root,
        /// Root of the latest block header.
        expected: Root,
    },
    /// The proposer was slashed.
    #[error("proposer {0} is slashed")]
    ProposerSlashed(ValidatorIndex),
    /// A signature is not a valid BLS signature encoding, or a key is not a valid key.
    #[error("a signature or key is malformed")]
    MalformedSignature,
    /// One or more signatures do not verify.
    #[error("a signature does not verify")]
    InvalidSignature,
    /// The withdrawals in the payload are not the expected ones.
    #[error("payload withdrawals are not the expected ones")]
    WithdrawalsMismatch,
    /// The payload does not build on the latest payload.
    #[error("payload does not build on the latest payload")]
    PayloadParentMismatch,
    /// The payload's randomness is not the current randao mix.
    #[error("payload randomness is not the randao mix")]
    PayloadRandaoMismatch,
    /// The payload's timestamp does not match the slot.
    #[error("payload timestamp does not match the slot")]
    PayloadTimestampMismatch,
    /// The block carries more blobs than the schedule allows.
    #[error("{count} blob commitments exceed the limit of {limit}")]
    TooManyBlobs {
        /// Commitments in the block.
        count: usize,
        /// The limit at this epoch.
        limit: u64,
    },
    /// The execution engine rejected the payload.
    #[error("the execution engine rejected the payload")]
    PayloadInvalid,
    /// The block carries deposits, which Fulu removed.
    #[error("block carries deposits")]
    DepositsNotAllowed,
    /// A proposer slashing does not show two distinct headers from one slot and proposer.
    #[error("proposer slashing is not slashable")]
    InvalidProposerSlashing,
    /// An attester slashing does not show a slashable pair of votes.
    #[error("attestations are not slashable")]
    AttestationsNotSlashable,
    /// An indexed attestation is empty, unsorted, or repeats an index.
    #[error("attesting indices are empty or unsorted")]
    InvalidAttestingIndices,
    /// An attester slashing slashed nobody.
    #[error("attester slashing slashed nobody")]
    NoValidatorSlashed,
    /// An attestation's target is neither the previous nor the current epoch.
    #[error("attestation target epoch {0} is not previous or current")]
    AttestationTargetEpochOutOfRange(Epoch),
    /// An attestation's target epoch is not the epoch of its slot.
    #[error("attestation target epoch is not the epoch of its slot")]
    AttestationTargetSlotMismatch,
    /// An attestation is included before its slot plus the inclusion delay.
    #[error("attestation is included too early")]
    AttestationTooEarly,
    /// An attestation sets the committee index field, which Electra retired.
    #[error("attestation committee index is not zero")]
    AttestationIndexNotZero,
    /// An attestation names a committee that does not exist.
    #[error("committee {0} does not exist")]
    UnknownCommittee(CommitteeIndex),
    /// An attestation has a committee with no participant.
    #[error("committee {0} has no participant")]
    EmptyCommittee(CommitteeIndex),
    /// An attestation's bitfield length is not the size of its committees.
    #[error("aggregation bits do not match the committees")]
    AggregationBitsLengthMismatch,
    /// An attestation's source is not the justified checkpoint.
    #[error("attestation source is not the justified checkpoint")]
    AttestationSourceMismatch,
    /// A voluntary exit breaks one of its rules.
    #[error("voluntary exit: {0}")]
    InvalidVoluntaryExit(&'static str),
    /// A credential change breaks one of its rules.
    #[error("credential change: {0}")]
    InvalidCredentialChange(&'static str),
    /// A state invariant broke while processing.
    #[error("state invariant broke: {0}")]
    State(#[from] StateError),
}

/// A full transition from a signed block that failed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TransitionError {
    /// Advancing through the empty slots failed.
    #[error("slot processing failed: {0}")]
    Slots(#[source] StateError),
    /// The block is invalid.
    #[error("invalid block: {0}")]
    Block(#[source] BlockError),
    /// The block's state root does not match the post-state.
    #[error("block claims state root {claimed}, post-state root is {computed}")]
    StateRootMismatch {
        /// Root the block claims.
        claimed: Root,
        /// Root of the computed post-state.
        computed: Root,
    },
}
