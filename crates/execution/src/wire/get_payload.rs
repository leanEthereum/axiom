//! The reply to engine_getPayloadV5.
//!
//! Defined in `src/engine/osaka.md`.
//!
//! ```text
//!     executionPayload       ExecutionPayloadV3
//!     blockValue             QUANTITY 256, wei paid to the fee recipient
//!     blobsBundle            BlobsBundleV2
//!     shouldOverrideBuilder  BOOLEAN
//!     executionRequests      array of DATA, EIP-7685 typed lists
//! ```

use axiom_json::Json;
use axiom_ssz::U256;
use axiom_types::{
    Preset,
    fulu::{ExecutionPayload, ExecutionRequests},
};

use super::{BlobsBundle, Fields, JsonCodec};
use crate::WireError;

/// A payload the engine built, with everything a proposer needs to publish it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetPayloadResponse<P: Preset> {
    /// The payload.
    pub execution_payload: ExecutionPayload<P>,

    /// Value of the payload to the fee recipient, in wei.
    pub block_value: U256,

    /// Blobs of the payload's blob transactions.
    pub blobs_bundle: BlobsBundle<P>,

    /// The engine's advice to prefer this payload over a builder's.
    pub should_override_builder: bool,

    /// Requests the payload's transactions triggered.
    pub execution_requests: ExecutionRequests<P>,
}

impl<P: Preset> JsonCodec for GetPayloadResponse<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("executionPayload", self.execution_payload.to_json()),
            ("blockValue", self.block_value.to_json()),
            ("blobsBundle", self.blobs_bundle.to_json()),
            (
                "shouldOverrideBuilder",
                self.should_override_builder.to_json(),
            ),
            ("executionRequests", self.execution_requests.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            execution_payload: fields.required("executionPayload")?,
            block_value: fields.required("blockValue")?,
            blobs_bundle: fields.required("blobsBundle")?,
            should_override_builder: fields.required("shouldOverrideBuilder")?,
            execution_requests: fields.required("executionRequests")?,
        })
    }
}
