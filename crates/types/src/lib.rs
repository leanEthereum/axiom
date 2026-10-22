//! Types of the Ethereum beacon chain: domain scalars, presets, and SSZ containers.
//!
//! # Overview
//!
//! Every container mirrors the consensus specs field for field.
//! The definitions follow the latest fork, Fulu, and cite the fork that introduced each one.
//!
//! Containers whose collections depend on the preset take it as a type parameter.
//! A mainnet block and a minimal block are therefore different types.
//!
//! # Examples
//!
//! ```
//! use axiom_ssz::Ssz;
//! use axiom_types::{Checkpoint, Epoch, Root};
//!
//! let checkpoint = Checkpoint {
//!     epoch: Epoch(5),
//!     root: Root::ZERO,
//! };
//! assert_eq!(Checkpoint::decode(&checkpoint.encode()), Ok(checkpoint));
//! ```

mod config;
pub mod constants;
mod containers;
mod preset;
mod primitives;

pub use axiom_ssz::Root;

// Invariant: indices and slots convert to vector positions without loss.
const _: () = assert!(usize::BITS == 64, "axiom targets 64-bit platforms only");
pub use config::{BlobParameters, BlobSchedule, ChainConfig, ConfigError, ForkName};
pub use containers::*;
pub use preset::{Mainnet, Minimal, Preset};
pub use primitives::*;

/// Containers of the Electra fork that Fulu changed.
pub mod electra {
    pub use crate::containers::electra::BeaconState;
}
