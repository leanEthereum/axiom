//! The operations a beacon node keeps for the blocks its validators propose.
//!
//! # Overview
//!
//! Gossip and the beacon API hand the node operations no block has included yet.
//! The pools keep them until a block can include them, or they can never matter again.
//!
//! - Attestations, aggregated per vote and committee.
//! - Proposer and attester slashings.
//! - Voluntary exits and withdrawal credential changes.
//! - Sync committee messages and contributions.
//! - Payload timeliness votes, from Gloas on.
//!
//! Each pool checks an operation on entry against the head state.
//! Packing checks it again under the rules of the block's fork, at the block's slot.
//!
//! # Signatures
//!
//! The pools trust the signatures they are given: their callers verify each one first.
//! Gossip rules do so on the network side, and the beacon API runs the same rules.
//!
//! The pools combine signatures in one place only, so another scheme can replace that step.
//!
//! Everything here is pure: no clock, no network, no disk.

mod aggregate;
mod attestations;
mod bits;
mod error;
mod exits;
mod fork;
mod packing;
mod payload_attestations;
mod pool;
mod slashings;
mod sync;

pub use aggregate::Aggregate;
pub use attestations::{AttestationPool, CommitteeAggregate, CommitteeVotes, Insertion, VoteGroup};
pub use bits::Bits;
pub use error::PoolError;
pub use exits::ValidatorRequests;
pub use fork::PoolFork;
pub use packing::{AttestationPacker, Eligibility, FLAGS, Ledger, PackedAttestation, RewardRule};
pub use payload_attestations::PayloadAttestationPool;
pub use pool::{BlockOperations, OperationPool};
pub use slashings::SlashingPool;
pub use sync::SyncPool;
