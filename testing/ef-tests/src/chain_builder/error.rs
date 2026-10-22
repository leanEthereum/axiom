//! Why a chain could not be built.

use axiom_state_transition::{StateError, TransitionError, gloas::EnvelopeError};
use axiom_types::{ForkName, Slot, ValidatorIndex, Version};
use thiserror::Error;

/// A genesis the builder cannot sign for, or a block it failed to build.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ChainBuilderError {
    /// The genesis state signs with another fork version than the configuration.
    #[error("genesis has fork version {state}, the configuration expects {config}")]
    ForkVersionMismatch {
        /// The current fork version of the genesis state.
        state: Version,
        /// The version the configuration gives the genesis epoch.
        config: Version,
    },
    /// A validator's key is not the pyspec test key of its index.
    #[error("validator {index} does not hold the pyspec test key {secret}")]
    KeyMismatch {
        /// The validator.
        index: ValidatorIndex,
        /// The secret scalar the pyspec helpers give that validator.
        secret: u64,
    },
    /// A proposer lies beyond the keys derived at genesis.
    #[error("validator {index} has no key, only {keys} keys exist")]
    NoKey {
        /// The proposer.
        index: ValidatorIndex,
        /// Keys derived at genesis.
        keys: usize,
    },
    /// An aggregate signature was asked of no signer.
    #[error("an aggregate signature needs at least one signer")]
    NoSigners,
    /// The state holds no root for a slot a vote names.
    #[error("the state holds no block root for slot {0}")]
    NoBlockRoot(Slot),
    /// A committee has more members than an attestation has bits.
    #[error("{count} attesters exceed the {limit} bits of an attestation")]
    TooManyAttesters {
        /// Members attesting together.
        count: usize,
        /// Bits an attestation holds.
        limit: usize,
    },
    /// A block body has fewer attestation places than the attestations built.
    #[error("{count} attestations exceed the {limit} a block carries")]
    TooManyAttestations {
        /// Attestations built.
        count: usize,
        /// Attestations a block carries.
        limit: usize,
    },
    /// A sync committee seat holds a key no validator has.
    #[error("sync committee seat {seat} holds a key no validator has")]
    UnknownSyncMember {
        /// The seat in the committee.
        seat: usize,
    },
    /// Advancing the state to the next slot failed.
    #[error("advancing to slot {slot} failed: {source}")]
    Slots {
        /// The slot of the block being built.
        slot: Slot,
        /// Why advancing failed.
        #[source]
        source: StateError,
    },
    /// The state at the block's slot does not yield the block's inputs.
    #[error("the state at slot {slot} yields no block inputs: {source}")]
    Inputs {
        /// The slot of the block being built.
        slot: Slot,
        /// Why the state did not yield them.
        #[source]
        source: StateError,
    },
    /// The state transition refused the block built for a slot.
    #[error("the block built for slot {slot} is invalid: {source}")]
    Block {
        /// The slot of the block.
        slot: Slot,
        /// Why the state transition refused it.
        #[source]
        source: TransitionError,
    },
    /// A block with a zero state root passed, so its true root stayed unknown.
    #[error("the block built for slot {0} passed with a zero state root")]
    ZeroStateRoot(Slot),
    /// The withdrawals due exceed what a payload carries.
    #[error("{count} withdrawals are due, a payload carries at most {limit}")]
    TooManyWithdrawals {
        /// Withdrawals due at the slot.
        count: usize,
        /// Withdrawals one payload carries.
        limit: usize,
    },
    /// Blob commitments were asked of a block whose body holds none.
    #[error("the {fork} block of slot {slot} holds no blob commitments in its body")]
    NoBlobCommitments {
        /// The slot of the block.
        slot: Slot,
        /// The fork of the block.
        fork: ForkName,
    },
    /// The blob commitments overflow the list a block body holds.
    #[error("{count} blob commitments for slot {slot}, a block body holds at most {limit}")]
    TooManyCommitments {
        /// The slot of the block.
        slot: Slot,
        /// Commitments asked for.
        count: usize,
        /// Commitments one body holds.
        limit: usize,
    },
    /// Supplied votes are of another fork's shape than the block's.
    #[error("the {fork} block of slot {slot} takes votes of another shape")]
    AttestationShape {
        /// The slot of the block.
        slot: Slot,
        /// The fork of the block.
        fork: ForkName,
    },
    /// A sync aggregate was supplied for a block of a fork without sync committees.
    #[error("the block of slot {0} predates sync committees")]
    NoSyncAggregate(Slot),
    /// The envelope built for a Gloas block does not reveal its bid.
    #[error("the envelope built for slot {slot} is invalid: {source}")]
    Envelope {
        /// The slot of the block that bid for the payload.
        slot: Slot,
        /// Why the envelope does not reveal the bid.
        #[source]
        source: EnvelopeError,
    },
}
