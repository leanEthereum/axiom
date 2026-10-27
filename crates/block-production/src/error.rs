//! Why a block could not be produced.

use axiom_operation_pool::PoolError;
use axiom_state_transition::{BlockError, StateError, TransitionError, gloas::EnvelopeError};
use axiom_types::{ForkName, Root, Slot, ValidatorIndex};
use thiserror::Error;

/// A proposal that cannot be built.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ProductionError {
    /// The slot is not after the parent's.
    #[error("cannot propose at slot {slot} on a parent at slot {parent}")]
    SlotNotAfterParent {
        /// The slot asked for.
        slot: Slot,
        /// The parent's slot.
        parent: Slot,
    },

    /// Advancing the parent's state to the slot failed.
    #[error("advancing to slot {slot}: {source}")]
    Slots {
        /// The slot asked for.
        slot: Slot,
        /// Why the state could not advance.
        #[source]
        source: StateError,
    },

    /// The proposer could not be elected.
    #[error("electing the proposer of slot {slot}: {source}")]
    Proposer {
        /// The slot.
        slot: Slot,
        /// Why no proposer came out.
        #[source]
        source: StateError,
    },

    /// The randao reveal is not the proposer's signature over the epoch.
    #[error("randao reveal at slot {slot} is not the signature of proposer {proposer}")]
    InvalidRandao {
        /// The slot.
        slot: Slot,
        /// The elected proposer.
        proposer: ValidatorIndex,
    },

    /// The state is not of the fork whose rules were asked for.
    #[error("the state is not a {0} state")]
    WrongState(ForkName),

    /// The execution input belongs to another fork than the slot's.
    #[error("a {fork} block cannot carry {execution}")]
    ExecutionMismatch {
        /// The slot's fork.
        fork: ForkName,
        /// What was given.
        execution: &'static str,
    },

    /// A list of the body overflows its bound.
    #[error("{count} {list} exceed the limit of {limit}")]
    TooMany {
        /// Which list.
        list: &'static str,
        /// Items given.
        count: usize,
        /// The list's bound.
        limit: usize,
    },

    /// A builder's header commits to withdrawals other than those due.
    #[error("builder header commits to withdrawals root {committed}, but {expected} are due")]
    WithdrawalsMismatch {
        /// The header's withdrawals root.
        committed: Root,
        /// Root of the withdrawals the state expects.
        expected: Root,
    },

    /// The parent's payload could not be settled on the state.
    #[error("settling the parent payload at slot {slot}: {source}")]
    ParentPayload {
        /// The slot.
        slot: Slot,
        /// Why the parent's requests failed.
        #[source]
        source: BlockError,
    },

    /// The parent's payload carried requests in another fork's container than the block reports.
    ///
    /// A block reports its parent payload's requests in its own fork's container.
    /// Requests of another fork's container cannot be restated without changing their root.
    #[error("a {fork} block cannot report the requests of a {parent} payload")]
    ParentRequestsFork {
        /// The fork of the block being built.
        fork: ForkName,
        /// The fork of the parent payload's requests.
        parent: ForkName,
    },

    /// The self-built envelope does not verify against the block's post-state.
    #[error("the envelope of the block at slot {slot} is invalid: {source}")]
    Envelope {
        /// The slot.
        slot: Slot,
        /// Why the envelope failed.
        #[source]
        source: EnvelopeError,
    },

    /// The operations could not be packed.
    #[error("packing operations: {0}")]
    Pool(#[from] PoolError),

    /// The withdrawals due could not be computed.
    #[error("computing withdrawals: {0}")]
    Withdrawals(#[source] StateError),

    /// The assembled block does not apply to its pre-state.
    #[error("the produced block at slot {slot} is invalid: {source}")]
    Invalid {
        /// The slot.
        slot: Slot,
        /// Why the block failed.
        #[source]
        source: TransitionError,
    },
}
