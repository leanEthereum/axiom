//! The engine API: how the beacon node drives its execution client.
//!
//! # Overview
//!
//! The consensus layer never executes transactions itself.
//! It hands each payload to an execution client and acts on the verdict.
//! It also tells that client which block is head, and asks it to build blocks.
//!
//! ```text
//!     beacon node calls                          execution client does
//!     engine_newPayloadV4(payload, ...)          execute, return a verdict
//!     engine_forkchoiceUpdatedV3(state, attrs)   set head, start a build
//!     engine_getPayloadV5(id)                    return the built payload, blobs, requests
//!     engine_getBlobsV2(hashes)                  return blobs from the mempool
//! ```
//!
//! Every call is JSON-RPC over HTTP, authenticated with a JWT.
//!
//! # Spec mapping
//!
//! Fulu on the consensus side pairs with Osaka on the execution side.
//! The engine API specs live in `ethereum/execution-apis`, under `src/engine/`.
//!
//! ```text
//!     method / structure            spec file           here
//!     engine_exchangeCapabilities   common.md           exchange capabilities call
//!     engine_newPayloadV4           prague.md           new payload call
//!     engine_forkchoiceUpdatedV3    cancun.md           fork choice update call
//!     engine_getPayloadV5           osaka.md            get payload call
//!     engine_getBlobsV2             osaka.md            get blobs call
//!     ExecutionPayloadV3            cancun.md           the consensus payload container
//!     WithdrawalV1                  shanghai.md         the consensus withdrawal container
//!     ForkchoiceStateV1             paris.md            fork choice state
//!     PayloadAttributesV3           cancun.md           payload attributes
//!     PayloadStatusV1               paris.md            payload status
//!     BlobsBundleV2, BlobAndProofV2 osaka.md            blob bundle, blob and proof
//!     executionRequests             prague.md, EIP-7685 requests list codec
//!     JWT HS256                     authentication.md   secret, token, verification
//!     QUANTITY and DATA             common.md           hex encodings, in the JSON crate
//! ```
//!
//! On the consensus side, the new payload call implements `notify_new_payload`,
//! and its requests list is `get_execution_requests_list`, both in the Electra beacon chain spec.

mod auth;
mod client;
mod error;
pub mod mock;
mod rpc;
pub mod wire;

pub use auth::{Claims, JwtError, JwtSecret, MAX_CLOCK_SKEW};
pub use client::{CAPABILITIES, EXECUTION_TIMEOUT, EngineClient, LOOKUP_TIMEOUT};
pub use error::{EngineError, EnvelopeError, RequestsError, WireError, WireErrorKind};
pub use rpc::RpcError;
pub use wire::{
    BlobAndProof, BlobsBundle, ForkchoiceState, ForkchoiceUpdated, GetPayloadResponse, JsonCodec,
    PayloadAttributes, PayloadId, PayloadStatus, PayloadStatusKind, SyncStatus,
};
