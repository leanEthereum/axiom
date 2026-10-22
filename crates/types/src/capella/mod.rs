//! The containers of Capella: withdrawals.
//!
//! Everything else is Bellatrix's.
//! See the Capella beacon chain and light client specs.

mod blinded_block;
mod block;
mod builder;
mod credential_change;
mod execution;
mod historical;
mod light_client;
mod state;
mod withdrawal;

pub use blinded_block::{BlindedBeaconBlock, BlindedBeaconBlockBody, SignedBlindedBeaconBlock};
pub use block::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock};
pub use builder::{BuilderBid, SignedBuilderBid};
pub use credential_change::{BlsToExecutionChange, SignedBlsToExecutionChange};
pub use execution::{ExecutionPayload, ExecutionPayloadHeader, NewPayloadRequest, Withdrawals};
pub use historical::HistoricalSummary;
pub use light_client::{
    ExecutionBranch, LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
    LightClientOptimisticUpdate, LightClientUpdate,
};
pub use state::{BeaconState, HistoricalSummaries};
pub use withdrawal::Withdrawal;

pub use crate::bellatrix::*;
