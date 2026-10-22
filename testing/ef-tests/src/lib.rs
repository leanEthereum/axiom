//! Runs the consensus spec test vectors against Axiom.
//!
//! # Overview
//!
//! The vectors are the interoperability contract between clients.
//! They live under `testing/vectors`, downloaded by this crate's Makefile.
//!
//! A vector directory reads as `tests/<preset>/<fork>/<runner>/<handler>/<suite>/<case>`.
//! Each handler of this crate knows how to run one kind of case.

mod case;
mod fields;
pub mod forks;
mod runners;
mod suite;

pub use case::{Case, Failure, Meta};
pub use fields::FieldNames;
pub use runners::{
    Applied, Blocks, ChainReplay, EpochProcessing, Fork, Genesis, GossipMessage, LightClient,
    MerkleProofs, Networking, OperationInput, Operations, PendingAttestationRewards, Rejection,
    Rewards, Shuffling, SszGeneric, SszStatic, StoreReplay, Transition, Verdict,
};
pub use suite::{Report, Runner, Suite, Vectors};
