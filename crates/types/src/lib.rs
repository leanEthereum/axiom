//! Types of the Ethereum beacon chain: domain scalars, presets, and SSZ containers.
//!
//! # Overview
//!
//! The root holds what every fork shares: domain scalars, presets, configuration, constants.
//! Each fork is a module holding the complete container set its spec sees.
//! A fork module re-exports its predecessor and defines only the containers its spec changed.
//! The combined module wraps the containers that differ by fork in one enum each.
//!
//! The accessor traits name groups of state fields, and each fork's state implements its groups.
//! Code that reads a group then serves every fork that has it.
//!
//! Every container mirrors the consensus specs field for field.
//! Containers whose collections depend on the preset take it as a type parameter.
//! A mainnet block and a minimal block are therefore different types.

pub mod accessors;
mod config;
pub mod constants;
mod preset;
mod primitives;

pub mod altair;
pub mod bellatrix;
pub mod capella;
pub mod combined;
pub mod deneb;
pub mod electra;
pub mod fulu;
pub mod gloas;
pub mod phase0;
pub mod vote;

pub use axiom_ssz::Root;

// Invariant: indices and slots convert to vector positions without loss.
const _: () = assert!(usize::BITS == 64, "axiom targets 64-bit platforms only");
pub use config::{BlobData, BlobParameters, BlobSchedule, ChainConfig, ConfigError, ForkName};
pub use preset::{Mainnet, Minimal, Preset};
pub use primitives::*;
