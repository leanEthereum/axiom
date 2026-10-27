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

mod blinded_block;
mod block;
mod builder_bid;
mod data_column;
mod envelope;
mod execution_payload;
mod signed_blinded_block;
mod signed_block;
mod state;

pub use blinded_block::{BlindedBeaconBlock, BlindedBlockError};
pub use block::{BeaconBlock, ExecutionHashes};
pub use builder_bid::SignedBuilderBid;
pub use data_column::DataColumnSidecar;
pub use envelope::SignedExecutionPayloadEnvelope;
pub use execution_payload::ExecutionPayload;
pub use signed_blinded_block::SignedBlindedBeaconBlock;
pub use signed_block::SignedBeaconBlock;
pub use state::BeaconState;
