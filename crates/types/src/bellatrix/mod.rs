//! The containers of Bellatrix: the merge with the execution layer.
//!
//! Everything else is Altair's.
//! See the Bellatrix beacon chain and fork choice specs.

mod block;
mod builder;
mod execution;
mod pow_block;
mod state;

pub use block::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock};
pub use builder::{SignedValidatorRegistrationV1, ValidatorRegistrationV1};
pub use execution::{
    ExecutionPayload, ExecutionPayloadHeader, ExtraData, LogsBloom, NewPayloadRequest, Transaction,
    Transactions,
};
pub use pow_block::PowBlock;
pub use state::BeaconState;

pub use crate::altair::*;
