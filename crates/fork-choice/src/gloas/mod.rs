//! Gloas: enshrined proposer-builder separation, see EIP-7732.
//!
//! A Gloas block commits to a builder's bid, and the payload follows in its own envelope.
//! The fork choice then weighs each block's payload apart from the block.
//! A payload timeliness committee votes on whether each payload arrived in time.
//!
//! This folder holds what the Gloas fork choice spec wrote out: the payload-aware head and the votes.
//! The handlers for envelopes and committee votes sit on the store.

mod head;
mod ptc;
mod tiebreak;
mod tree_ghost;

pub(crate) use head::BoostParent;
pub use head::PayloadGhost;
pub use ptc::{PayloadVotes, PtcVotes};
pub(crate) use tiebreak::PayloadTiebreak;
pub(crate) use tree_ghost::{PayloadMark, TreePayloadGhost};
