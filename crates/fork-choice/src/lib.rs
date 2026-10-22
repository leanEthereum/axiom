//! LMD-GHOST and Casper FFG fork choice, over a pure store.
//!
//! # Overview
//!
//! The fork choice picks the canonical head from every block a node has seen.
//!
//! - Casper FFG finalizes checkpoints: no head may conflict with the finalized one.
//! - LMD-GHOST walks from the justified checkpoint toward the subtree with the most stake.
//!
//! Together they form Gasper, see Buterin et al., "Combining GHOST and Casper", 2020.
//!
//! The store is a pure state machine.
//! Time, blocks, votes, and data availability verdicts are inputs, never side effects.

mod availability;
mod block_tree;
mod checkpoints;
mod committee_weight;
mod error;
mod fast_confirmation;
mod head;
mod payload;
mod proposer_head;
mod store;
mod votes;

pub use availability::DataAvailability;
pub use block_tree::{BlockNode, BlockTree, ExecutionStatus};
pub use error::ForkChoiceError;
pub use fast_confirmation::FastConfirmation;
pub use head::Ghost;
pub use payload::PayloadStatus;
pub use store::Store;
pub use votes::{LatestMessage, Votes};
