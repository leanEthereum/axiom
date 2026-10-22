//! The containers of Deneb: blobs, see EIP-4844.
//!
//! Everything else is Capella's.
//! See the Deneb beacon chain, networking, and light client specs.

mod blob;
mod block;
mod block_contents;
mod execution;
mod light_client;
mod state;

pub use blob::{Blob, BlobIdentifier, BlobSidecar};
pub use block::{BeaconBlock, BeaconBlockBody, BlobKzgCommitments, SignedBeaconBlock};
pub use block_contents::SignedBlockContents;
pub use execution::{ExecutionPayload, ExecutionPayloadHeader, NewPayloadRequest, VersionedHashes};
pub use light_client::{
    LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
    LightClientOptimisticUpdate, LightClientUpdate,
};
pub use state::BeaconState;

pub use crate::capella::*;
