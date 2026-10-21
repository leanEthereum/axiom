//! Reasons a state transition fails.
//!
//! A block that breaks a rule is invalid, and the node discards it.
//! A state that breaks an invariant is corrupt, which a valid chain never produces.

use std::{error::Error, fmt};

use axiom_types::{CommitteeIndex, Epoch, Root, Slot, ValidatorIndex};

/// A state that violates an invariant the protocol relies on.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateError {
    /// A validator index points past the registry.
    UnknownValidator(ValidatorIndex),
    /// A block root was read outside the window the state keeps.
    BlockRootOutOfRange {
        /// The slot asked for.
        slot: Slot,
        /// The state's slot.
        state_slot: Slot,
    },
    /// Committees were asked for an epoch other than the previous, current, or next one.
    EpochOutOfRange {
        /// The epoch asked for.
        epoch: Epoch,
        /// The state's epoch.
        current: Epoch,
    },
    /// An epoch has no active validator, so no committee or proposer exists.
    NoActiveValidators(Epoch),
    /// A balance or counter overflowed 64 bits.
    Overflow,
    /// A list in the state is at its SSZ limit.
    ListFull,
    /// Slot processing was asked to go backwards or stand still.
    SlotNotInFuture {
        /// The target slot.
        target: Slot,
        /// The state's slot.
        state_slot: Slot,
    },
    /// The next sync committee could not be aggregated.
    InvalidSyncCommittee,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownValidator(index) => write!(f, "validator {index} is not in the registry"),
            Self::BlockRootOutOfRange { slot, state_slot } => {
                write!(
                    f,
                    "block root of slot {slot} is not kept at slot {state_slot}"
                )
            }
            Self::EpochOutOfRange { epoch, current } => {
                write!(
                    f,
                    "committees of epoch {epoch} are not known at epoch {current}"
                )
            }
            Self::NoActiveValidators(epoch) => write!(f, "epoch {epoch} has no active validator"),
            Self::Overflow => f.write_str("arithmetic overflow"),
            Self::ListFull => f.write_str("a state list is at its limit"),
            Self::SlotNotInFuture { target, state_slot } => {
                write!(
                    f,
                    "target slot {target} is not after state slot {state_slot}"
                )
            }
            Self::InvalidSyncCommittee => f.write_str("the next sync committee does not aggregate"),
        }
    }
}

impl Error for StateError {}

/// A block that breaks a rule of block processing.
///
/// Each variant names the assertion of the spec that failed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockError {
    /// The block's slot is not the state's slot.
    SlotMismatch {
        /// The block's slot.
        block: Slot,
        /// The state's slot.
        state: Slot,
    },
    /// The block is not newer than the latest block.
    NotNewerThanParent,
    /// The block names the wrong proposer.
    WrongProposer {
        /// The proposer the block names.
        claimed: ValidatorIndex,
        /// The proposer of the slot.
        expected: ValidatorIndex,
    },
    /// The block's parent is not the latest block.
    ParentMismatch {
        /// The parent the block names.
        claimed: Root,
        /// Root of the latest block header.
        expected: Root,
    },
    /// The proposer was slashed.
    ProposerSlashed(ValidatorIndex),
    /// A signature is not a valid BLS signature encoding, or a key is not a valid key.
    MalformedSignature,
    /// One or more signatures do not verify.
    InvalidSignature,
    /// The withdrawals in the payload are not the expected ones.
    WithdrawalsMismatch,
    /// The payload does not build on the latest payload.
    PayloadParentMismatch,
    /// The payload's randomness is not the current randao mix.
    PayloadRandaoMismatch,
    /// The payload's timestamp does not match the slot.
    PayloadTimestampMismatch,
    /// The block carries more blobs than the schedule allows.
    TooManyBlobs {
        /// Commitments in the block.
        count: usize,
        /// The limit at this epoch.
        limit: u64,
    },
    /// The execution engine rejected the payload.
    PayloadInvalid,
    /// The block carries deposits, which Fulu removed.
    DepositsNotAllowed,
    /// A proposer slashing does not show two distinct headers from one slot and proposer.
    InvalidProposerSlashing,
    /// An attester slashing does not show a slashable pair of votes.
    AttestationsNotSlashable,
    /// An indexed attestation is empty, unsorted, or repeats an index.
    InvalidAttestingIndices,
    /// An attester slashing slashed nobody.
    NoValidatorSlashed,
    /// An attestation's target is neither the previous nor the current epoch.
    AttestationTargetEpochOutOfRange(Epoch),
    /// An attestation's target epoch is not the epoch of its slot.
    AttestationTargetSlotMismatch,
    /// An attestation is included before its slot plus the inclusion delay.
    AttestationTooEarly,
    /// An attestation sets the committee index field, which Electra retired.
    AttestationIndexNotZero,
    /// An attestation names a committee that does not exist.
    UnknownCommittee(CommitteeIndex),
    /// An attestation has a committee with no participant.
    EmptyCommittee(CommitteeIndex),
    /// An attestation's bitfield length is not the size of its committees.
    AggregationBitsLengthMismatch,
    /// An attestation's source is not the justified checkpoint.
    AttestationSourceMismatch,
    /// A voluntary exit breaks one of its rules.
    InvalidVoluntaryExit(&'static str),
    /// A credential change breaks one of its rules.
    InvalidCredentialChange(&'static str),
    /// A state invariant broke while processing.
    State(StateError),
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SlotMismatch { block, state } => {
                write!(f, "block slot {block} is not state slot {state}")
            }
            Self::NotNewerThanParent => f.write_str("block is not newer than the latest block"),
            Self::WrongProposer { claimed, expected } => {
                write!(
                    f,
                    "block names proposer {claimed}, slot proposer is {expected}"
                )
            }
            Self::ParentMismatch { claimed, expected } => {
                write!(
                    f,
                    "block parent {claimed} is not the latest block {expected}"
                )
            }
            Self::ProposerSlashed(index) => write!(f, "proposer {index} is slashed"),
            Self::MalformedSignature => f.write_str("a signature or key is malformed"),
            Self::InvalidSignature => f.write_str("a signature does not verify"),
            Self::WithdrawalsMismatch => {
                f.write_str("payload withdrawals are not the expected ones")
            }
            Self::PayloadParentMismatch => {
                f.write_str("payload does not build on the latest payload")
            }
            Self::PayloadRandaoMismatch => f.write_str("payload randomness is not the randao mix"),
            Self::PayloadTimestampMismatch => {
                f.write_str("payload timestamp does not match the slot")
            }
            Self::TooManyBlobs { count, limit } => {
                write!(f, "{count} blob commitments exceed the limit of {limit}")
            }
            Self::PayloadInvalid => f.write_str("the execution engine rejected the payload"),
            Self::DepositsNotAllowed => f.write_str("block carries deposits"),
            Self::InvalidProposerSlashing => f.write_str("proposer slashing is not slashable"),
            Self::AttestationsNotSlashable => f.write_str("attestations are not slashable"),
            Self::InvalidAttestingIndices => f.write_str("attesting indices are empty or unsorted"),
            Self::NoValidatorSlashed => f.write_str("attester slashing slashed nobody"),
            Self::AttestationTargetEpochOutOfRange(epoch) => {
                write!(
                    f,
                    "attestation target epoch {epoch} is not previous or current"
                )
            }
            Self::AttestationTargetSlotMismatch => {
                f.write_str("attestation target epoch is not the epoch of its slot")
            }
            Self::AttestationTooEarly => f.write_str("attestation is included too early"),
            Self::AttestationIndexNotZero => f.write_str("attestation committee index is not zero"),
            Self::UnknownCommittee(index) => write!(f, "committee {index} does not exist"),
            Self::EmptyCommittee(index) => write!(f, "committee {index} has no participant"),
            Self::AggregationBitsLengthMismatch => {
                f.write_str("aggregation bits do not match the committees")
            }
            Self::AttestationSourceMismatch => {
                f.write_str("attestation source is not the justified checkpoint")
            }
            Self::InvalidVoluntaryExit(rule) => write!(f, "voluntary exit: {rule}"),
            Self::InvalidCredentialChange(rule) => write!(f, "credential change: {rule}"),
            Self::State(error) => write!(f, "state invariant broke: {error}"),
        }
    }
}

impl Error for BlockError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::State(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StateError> for BlockError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

/// A full transition from a signed block that failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// Advancing through the empty slots failed.
    Slots(StateError),
    /// The block is invalid.
    Block(BlockError),
    /// The block's state root does not match the post-state.
    StateRootMismatch {
        /// Root the block claims.
        claimed: Root,
        /// Root of the computed post-state.
        computed: Root,
    },
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Slots(error) => write!(f, "slot processing failed: {error}"),
            Self::Block(error) => write!(f, "invalid block: {error}"),
            Self::StateRootMismatch { claimed, computed } => {
                write!(
                    f,
                    "block claims state root {claimed}, post-state root is {computed}"
                )
            }
        }
    }
}

impl Error for TransitionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Slots(error) => Some(error),
            Self::Block(error) => Some(error),
            Self::StateRootMismatch { .. } => None,
        }
    }
}
