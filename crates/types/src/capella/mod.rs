//! The containers of Capella: withdrawals.
//!
//! Everything else is Bellatrix's.
//! See the Capella beacon chain and light client specs.

mod block;
mod credential_change;
mod execution;
mod historical;
mod light_client;
mod state;
mod withdrawal;

pub use block::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock};
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
