//! The beacon chain state transition function, as a pure library, for every fork.
//!
//! # Overview
//!
//! The state transition maps a state and a signed block to the next state.
//! It runs the empty slots up to the block, then the block itself.
//!
//! 1. Slot processing advances the state from slot s to the block's slot b.
//! 2. Every epoch boundary on the way runs the epoch transition.
//! 3. Every fork boundary on the way upgrades the state to the next fork.
//! 4. Block processing applies the block, giving the post-state at slot b.
//!
//! Everything here is a function of its inputs.
//! No clock, no network, no disk: the execution engine's verdict is an input too.
//!
//! # Layout
//!
//! The crate root holds what no fork changed.
//! That is the state wrapper and its caches, committees, shuffling, sampling, and signatures.
//! The block and epoch processors live there too, holding what every fork's processing shares.
//!
//! Each fork has a folder holding only what its spec introduced or rewrote.
//! A step lives in the folder of the fork that wrote its current version.
//! Later forks call it directly, generic over the field groups it reads.
//!
//! Each fork's folder implements the fork trait on that fork's state type.
//! That implementation is the fork's table of contents.
//! It lists the epoch steps and block steps, and which fork's version of each one it runs.
//!
//! The state wrapper matches the fork once and hands the concrete state to that implementation.
//! Below that one match, all code is monomorphic.
//!
//! # Adding a fork
//!
//! 1. Add the fork's types, its combined variants, and its constant tables in the types crate.
//! 2. Create a folder named after the fork, beside the others.
//! 3. In it, implement the upgrade trait: the previous fork's state, by value, to this one.
//! 4. Implement the fork trait on the new state.
//!    List the epoch steps in spec order, adding variants to the step enum for new steps.
//!    Hand inherited steps to the previous fork's epoch type, and write the rewritten ones.
//! 5. Write block processing in the order the spec gives, reusing earlier steps by name.
//!    A rewritten rule for an operation type the fork keeps gets a wrapper type in the folder.
//!    Each version of the rule then stays its own type.
//! 6. Add the fork's arm to the state wrapper's dispatch and upgrade, and a signed block impl.
//!
//! Nothing outside the new folder changes, apart from those few arms.
//!
//! Each item cites the spec function it implements, and the fork whose spec defines it.

mod active_balance;
pub mod altair;
pub mod bellatrix;
mod block;
mod cached_state;
mod caches;
pub mod capella;
mod committees;
pub mod deneb;
pub mod electra;
mod epoch;
mod error;
mod execution;
mod fork;
pub mod fulu;
pub mod gloas;
pub mod phase0;
mod pubkeys;
mod registry;
mod sampling;
mod shuffle;
mod signatures;
mod state;

pub use active_balance::ActiveBalance;
pub use block::{BlockProcessor, Operation};
pub use cached_state::CachedState;
pub use caches::Caches;
pub use committees::EpochCommittees;
pub use epoch::{EpochProcessor, EpochStep};
pub use error::{BlockError, StateError, TransitionError};
pub use execution::{ExecutionEngine, KnownVerdict, PayloadEngine};
pub use fork::{Fork, Upgrade};
pub use pubkeys::PubkeyCache;
pub use registry::Registry;
pub use shuffle::SwapOrNot;
pub use signatures::{SignatureBatch, Verification};
pub use state::{SignedBlock, State};
