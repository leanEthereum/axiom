//! Building the block a validator proposes, for every fork, as a pure library.
//!
//! # Overview
//!
//! A proposal gathers what every fork's block shares, then lets the slot's fork assemble it.
//!
//! - The randao reveal and graffiti come from the validator.
//! - The eth1 vote follows the honest validator's rule, until deposits arrive as requests.
//! - Operations and the sync aggregate come from the operation pool.
//! - The payload comes from the node's engine, or a builder's header, or a Gloas bid.
//!
//! The block is applied to its pre-state once, which gives its state root and its value.
//! Everything here is pure: the node fetches payloads and bids, and the validator signs.

mod body;
mod error;
mod eth1;
mod execution;
mod fork;
mod produced;
mod producer;
mod trial;

pub use body::{BodyParts, Bounded};
pub use error::ProductionError;
pub use eth1::{Eth1Candidate, Eth1Vote};
pub use execution::{
    BuilderBoost, ExecutionChoice, GloasBid, LocalBuild, LocalPayload, ParentPayload, Wei,
};
pub use fork::BlockFork;
pub use produced::{Built, ProducedBlock, Proposal};
pub use producer::{BlockProducer, PayloadRequest, ProposalRequest, RandaoCheck};
pub use trial::Trial;
