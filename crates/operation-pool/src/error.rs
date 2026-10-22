//! Why the pool refused an operation, or could not pack one.

use axiom_bls::BlsError;
use axiom_state_transition::{BlockError, StateError};
use axiom_types::{CommitteeIndex, Epoch, ForkName, Slot, ValidatorIndex};
use thiserror::Error;

/// An operation the pool cannot keep, or a block it cannot fill.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PoolError {
    /// Two aggregates to merge share a signer, who would count twice.
    #[error("aggregates to merge share a signer")]
    OverlappingSigners,

    /// A signature is not a valid curve point.
    #[error("signature is not a valid point: {0}")]
    Signature(#[source] BlsError),

    /// A committee's votes disagree on how many members it has.
    #[error("committee of {expected} members got a vote with {actual} bits")]
    CommitteeLengthMismatch {
        /// Bits in the committee's earlier votes.
        expected: usize,
        /// Bits in the refused vote.
        actual: usize,
    },

    /// An attestation names a number of committees other than one.
    #[error("attestation names {0} committees, expected exactly one")]
    CommitteeCount(usize),

    /// A vote's signer does not sit in the committee it names.
    #[error("validator {validator} is not a member of committee {committee}")]
    NotInCommittee {
        /// The signer.
        validator: ValidatorIndex,
        /// The committee named.
        committee: CommitteeIndex,
    },

    /// A list of signers exceeds its container's bound.
    #[error("{count} signers exceed the limit of {limit}")]
    TooManySigners {
        /// Signers given.
        count: usize,
        /// The container's bound.
        limit: usize,
    },

    /// A validator index names no validator.
    #[error("validator {index} is not in the registry of {registry_size}")]
    UnknownValidator {
        /// The index.
        index: ValidatorIndex,
        /// Validators in the registry.
        registry_size: usize,
    },

    /// The operation can no longer change anything: its validators are slashed or exited.
    #[error("operation for validator {0} is already in effect")]
    AlreadyInEffect(ValidatorIndex),

    /// The two votes of an attester slashing do not conflict.
    #[error("the two votes are neither a double vote nor a surround vote")]
    NotSlashable,

    /// A proposer slashing's headers are not two different blocks of one proposer and slot.
    #[error("headers at slots {first} and {second} are not a double proposal")]
    NotDoubleProposal {
        /// Slot of the first header.
        first: Slot,
        /// Slot of the second header.
        second: Slot,
    },

    /// An exit names an epoch still in the future.
    #[error("exit at epoch {exit} lies after the current epoch {current}")]
    ExitInFuture {
        /// The exit's epoch.
        exit: Epoch,
        /// The state's epoch.
        current: Epoch,
    },

    /// A credential change for a validator without BLS withdrawal credentials.
    #[error("validator {0} has no BLS withdrawal credentials to change")]
    NotBlsCredentials(ValidatorIndex),

    /// A payload vote from a validator outside the slot's committee.
    #[error("validator {validator} has no seat in the payload committee of slot {slot}")]
    NotInPayloadCommittee {
        /// The voter.
        validator: ValidatorIndex,
        /// The slot voted on.
        slot: Slot,
    },

    /// The state is of another fork than the block being packed.
    #[error("packing a {expected} block on a {actual} state")]
    WrongFork {
        /// The block's fork.
        expected: ForkName,
        /// The state's fork.
        actual: ForkName,
    },

    /// A sync committee message from a validator outside the committee.
    #[error("validator {0} has no seat in the sync committee")]
    NotInSyncCommittee(ValidatorIndex),

    /// The state could not answer a question the packing asked.
    #[error("state: {0}")]
    State(#[from] StateError),

    /// A recorded vote of the state could not be resolved.
    #[error("block rule: {0}")]
    Block(#[from] BlockError),
}
