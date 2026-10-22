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
mod runners;
mod suite;

pub use case::{Case, Failure, Meta, assert_container_eq};
pub use runners::{
    BEACON_STATE_FIELDS, Blocks, ChainReplay, EpochProcessing, Fork, LightClient, MerkleProofs,
    Networking, Operations, Rewards, Shuffling, SszStatic, StoreReplay, Transition, case_config,
    config_of,
};
pub use suite::{Report, Runner, Suite, Vectors};
