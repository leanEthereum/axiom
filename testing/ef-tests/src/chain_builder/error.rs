//! Why a chain could not be built.

use axiom_state_transition::{StateError, TransitionError, gloas::EnvelopeError};
use axiom_types::{Slot, ValidatorIndex, Version};
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
