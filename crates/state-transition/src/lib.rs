//! The beacon chain state transition function, as a pure library.
//!
//! # Overview
//!
//! The state transition maps a state and a signed block to the next state.
//! It runs the empty slots up to the block, then the block itself.
//!
//! ```text
//! state(slot s) --process_slots--> state(slot b) --process_block--> state'(slot b)
//!                  epoch transitions on the way
//! ```
//!
//! Everything here is a function of its inputs.
//! No clock, no network, no disk: the execution engine's verdict is an input too.
//!
//! The code follows the consensus specs for the Fulu fork, step by step.
//! Each item cites the spec function it implements.

mod block;
mod committees;
mod epoch;
mod error;
mod execution;
mod pubkeys;
mod shuffle;
mod signatures;
mod state;
mod upgrade;

pub use block::{BlockProcessor, ExpectedWithdrawals, Operation};
pub use committees::EpochCommittees;
pub use epoch::{Deltas, EpochProcessor, EpochStep};
pub use error::{BlockError, StateError, TransitionError};
pub use execution::{ExecutionEngine, KnownVerdict};
pub use pubkeys::PubkeyCache;
pub use shuffle::SwapOrNot;
pub use signatures::{SignatureBatch, Verification};
pub use state::State;
