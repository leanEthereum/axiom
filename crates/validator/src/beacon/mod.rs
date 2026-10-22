//! The beacon API client: one node over HTTP, and a set of nodes with fallback.
//!
//! # Overview
//!
//! A validator client reaches the chain only through the standard beacon API.
//! See the `ethereum/beacon-APIs` repository.
//!
//! - Blocks travel as SSZ, which every fork's container defines.
//! - Every other message travels as JSON, which every beacon node serves.
//!
//! Forks differ in the shape of blocks, votes, and aggregates.
//! The shape is chosen once, from the fork of the slot, where a message is built or read.

mod attestations;
mod beacon_api;
mod blocks;
pub(crate) mod client;
mod error;
mod node_api;
mod nodes;
mod topic;
mod validator_api;

pub use attestations::{Aggregate, AggregateAndProof, PoolAttestation, SignedAggregate};
pub use beacon_api::BeaconEndpoints;
pub use blocks::{ProducedBlock, SignedProposal};
pub use client::BeaconClient;
pub use error::BeaconError;
pub use node_api::NodeEndpoints;
pub use nodes::{BeaconNodes, Health};
pub use topic::ApiTopic;
pub use validator_api::ValidatorEndpoints;
