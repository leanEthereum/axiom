//! LMD-GHOST and Casper FFG fork choice, over a pure store, for every fork.
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
//!
//! # Layout
//!
//! Phase0 through Fulu share one rule set, with blocks and states read through the combined enums.
//! Votes enter as fork-agnostic views, converted once from each fork's container.
//!
//! Heads are read off a weight tree that votes update by change, see the weight tree module.
//! The views that recount every vote stay as the reference the fast path is pinned to.
//!
//! Two forks wrote rules of their own, and each has a folder.
//! Bellatrix checks the merge block against the terminal proof-of-work block.
//! Gloas weighs each block's payload apart from the block, with a payload committee voting on it.

mod availability;
pub mod bellatrix;
mod block_tree;
mod checkpoints;
mod committee_weight;
mod error;
mod fast_confirmation;
pub mod gloas;
mod head;
mod node;
mod payload;
mod proposer_head;
mod store;
mod timeliness;
mod tree_ghost;
mod votes;
mod weight_tree;

pub use availability::DataAvailability;
pub use block_tree::{BlockNode, BlockTree, ExecutionStatus, PayloadArrival};
pub use error::ForkChoiceError;
pub use fast_confirmation::FastConfirmation;
pub use gloas::{PayloadGhost, PayloadVotes};
pub use head::Ghost;
pub use node::{ForkChoiceNode, NodePayload};
pub use payload::PayloadStatus;
pub use store::Store;
pub use timeliness::Timeliness;
pub use votes::{LatestMessage, VoteOrder, Votes};
