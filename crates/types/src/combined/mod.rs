//! Containers of any fork, one enum per container that forks change.
//!
//! # Overview
//!
//! A node receives blocks and states without knowing their fork in advance.
//! These enums carry one variant per fork and the few methods every fork answers alike.
//! Decoding takes the fork, or reads the slot first and asks the configuration.
//!
//! Dispatch happens once, at that boundary.
//! Below it, code matches on the variant and works on one concrete fork type.

mod block;
mod signed_block;
mod state;

pub use block::{BeaconBlock, ExecutionHashes};
pub use signed_block::SignedBeaconBlock;
pub use state::BeaconState;
