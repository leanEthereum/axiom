//! The engine API: how the beacon node drives its execution client.
//!
//! # Overview
//!
//! The consensus layer never executes transactions itself.
//! It hands each payload to an execution client and acts on the verdict.
//! It also tells that client which block is head, and asks it to build blocks.
//!
//! ```text
//!     beacon node calls                   execution client does
//!     engine_newPayload(payload, ...)     execute, return a verdict
//!     engine_forkchoiceUpdated(state, a)  set head, start a build
//!     engine_getPayload(id)               return the built payload, blobs, requests
//!     engine_getBlobs(hashes)             return blobs from the mempool
//! ```
//!
//! Every call is JSON-RPC over HTTP, authenticated with a JWT.
//! Each fork calls its own version of each method, chosen in one table.
//! Phase0 and Altair predate the merge and call none.
//!
//! # Spec mapping
//!
//! Each consensus fork pairs with an execution fork.
//! The engine API specs live in `ethereum/execution-apis`, under `src/engine/`.
//!
//! ```text
//!     consensus  execution  spec file      newPayload  forkchoiceUpdated  getPayload  getBlobs
//!     Bellatrix  Paris      paris.md       V1          V1                 V1          none
//!     Capella    Shanghai   shanghai.md    V2          V2                 V2          none
//!     Deneb      Cancun     cancun.md      V3          V3                 V3          V1
//!     Electra    Prague     prague.md      V4          V3                 V4          V1
//!     Fulu       Osaka      osaka.md       V4          V3                 V5          V2
//!     Gloas      Amsterdam  amsterdam.md   V5          V4                 V6          V2
//! ```
//!
//! The structures, with the file that defines each and the consensus container it maps onto:
//!
//! ```text
//!     structure                       spec file           here
//!     engine_exchangeCapabilities     common.md           exchange capabilities call
//!     ExecutionPayloadV1              paris.md            the Bellatrix payload
//!     ExecutionPayloadV2              shanghai.md         the Capella payload
//!     ExecutionPayloadV3              cancun.md           the Deneb payload, to Fulu
//!     ExecutionPayloadV4              amsterdam.md        the Gloas payload
//!     WithdrawalV1                    shanghai.md         the Capella withdrawal
//!     ForkchoiceStateV1               paris.md            fork choice state
//!     PayloadAttributesV1 to V4       per fork            build attributes, one per version
//!     PayloadStatusV1                 paris.md            payload status
//!     BlobsBundleV1, BlobAndProofV1   cancun.md           blobs with one proof each
//!     BlobsBundleV2, BlobAndProofV2   osaka.md            blobs with cell proofs
//!     executionRequests               prague.md, EIP-7685 requests list codec
//!     JWT HS256                       authentication.md   secret, token, verification
//!     QUANTITY and DATA               common.md           hex encodings, in the JSON crate
//! ```
//!
//! On the consensus side, the new payload call implements `notify_new_payload`.
//! Up to Fulu, `process_execution_payload` builds its request.
//! In Gloas, `verify_execution_payload_envelope` of the fork choice spec builds it.
//!
//! The requests list is `get_execution_requests_list`, in the Electra and Gloas beacon chain specs.

mod auth;
mod client;
mod error;
mod methods;
pub mod mock;
mod new_payload;
mod rpc;
pub mod wire;

pub use auth::{Claims, JwtError, JwtSecret, MAX_CLOCK_SKEW};
pub use client::{EngineClient, LOOKUP_TIMEOUT};
pub use error::{
    EngineError, EnvelopeError, NewPayloadError, RequestsError, WireError, WireErrorKind,
};
pub use methods::{
    CAPABILITIES, EXECUTION_TIMEOUT, EngineMethods, ForkchoiceVersion, GetBlobsVersion,
    GetPayloadVersion, NewPayloadVersion,
};
pub use new_payload::NewPayload;
pub use rpc::RpcError;
pub use wire::{
    BlobAndProofV1, BlobAndProofV2, BlobsBundleV1, BlobsBundleV2, ForkchoiceState,
    ForkchoiceUpdated, GetBlobsResponse, GetPayloadResponse, GetPayloadResponseV2,
    GetPayloadResponseV3, GetPayloadResponseV4, GetPayloadResponseV5, GetPayloadResponseV6,
    JsonCodec, PayloadAttributes, PayloadAttributesV1, PayloadAttributesV2, PayloadAttributesV3,
    PayloadAttributesV4, PayloadId, PayloadStatus, PayloadStatusKind, SyncStatus,
};
