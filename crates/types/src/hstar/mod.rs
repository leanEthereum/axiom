//! The containers of Hstar: the post-quantum validator key registry, see EIP-8450.
//!
//! Each validator registers one leanXMSS key.
//! The key stays dormant until a later fork switches duties to it.
//! Blocks carry registrations, and execution requests carry owner authorizations.
//! Everything else is Gloas's.

mod block;
mod block_contents;
mod envelope;
mod execution;
mod registry;
mod state;
mod xmss;

pub use block::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock};
pub use block_contents::BlockContents;
pub use envelope::{ExecutionPayloadEnvelope, SignedExecutionPayloadEnvelope};
pub use execution::{ExecutionRequests, NewPayloadRequest};
pub use registry::{
    PendingPqKeyAuthorization, PendingPqKeyAuthorizations, PqKeyAuthorizationRequest,
    PqKeyAuthorizationRequests, PqKeyRegistration, PqKeyRegistrations, PqPublicKeys,
    SignedPqKeyRegistration, ValidatorPqPublicKeys,
};
pub use state::BeaconState;
pub use xmss::{XmssChainValues, XmssLayerSignature, XmssMerklePath, XmssSignature};

pub use crate::gloas::*;
