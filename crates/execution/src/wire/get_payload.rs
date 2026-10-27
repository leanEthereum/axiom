//! The replies to engine_getPayload, versions V1 to V6.
//!
//! Version 1 returns the bare payload; every later version wraps it in an object.
//! Each column is one member of the reply object, by a short name.
//!
//! ```text
//!     version  payload    value     blobs          override   requests
//!     V1       V1, bare
//!     V2       V2         QUANTITY
//!     V3       V3         QUANTITY  BlobsBundleV1  BOOLEAN
//!     V4       V3         QUANTITY  BlobsBundleV1  BOOLEAN    array of DATA
//!     V5       V3         QUANTITY  BlobsBundleV2  BOOLEAN    array of DATA
//!     V6       V4         QUANTITY  BlobsBundleV2  BOOLEAN    array of DATA
//! ```
//!
//! The block value is in wei, paid to the fee recipient.
//! See the getPayload sections of each fork's file under `src/engine/`.

use axiom_json::Json;
use axiom_ssz::U256;
use axiom_types::{Preset, bellatrix, capella, deneb, electra, gloas};

use super::{BlobsBundleV1, BlobsBundleV2, Fields, JsonCodec, RequestsList};
use crate::{GetPayloadVersion, WireError};

/// A Capella payload the engine built, with its value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetPayloadResponseV2<P: Preset> {
    /// The payload.
    pub execution_payload: capella::ExecutionPayload<P>,

    /// Value of the payload to the fee recipient, in wei.
    pub block_value: U256,
}

impl<P: Preset> JsonCodec for GetPayloadResponseV2<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("executionPayload", self.execution_payload.to_json()),
            ("blockValue", self.block_value.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            execution_payload: fields.required("executionPayload")?,
            block_value: fields.required("blockValue")?,
        })
    }
}

/// A Deneb payload the engine built, with its blobs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetPayloadResponseV3<P: Preset> {
    /// The payload.
    pub execution_payload: deneb::ExecutionPayload<P>,

    /// Value of the payload to the fee recipient, in wei.
    pub block_value: U256,

    /// Blobs of the payload's blob transactions, one proof each.
    pub blobs_bundle: BlobsBundleV1<P>,

    /// The engine's advice to prefer this payload over a builder's.
    pub should_override_builder: bool,
}

impl<P: Preset> JsonCodec for GetPayloadResponseV3<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("executionPayload", self.execution_payload.to_json()),
            ("blockValue", self.block_value.to_json()),
            ("blobsBundle", self.blobs_bundle.to_json()),
            (
                "shouldOverrideBuilder",
                self.should_override_builder.to_json(),
            ),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            execution_payload: fields.required("executionPayload")?,
            block_value: fields.required("blockValue")?,
            blobs_bundle: fields.required("blobsBundle")?,
            should_override_builder: fields.required("shouldOverrideBuilder")?,
        })
    }
}

/// An Electra payload the engine built, with its blobs and requests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetPayloadResponseV4<P: Preset> {
    /// The payload.
    pub execution_payload: deneb::ExecutionPayload<P>,

    /// Value of the payload to the fee recipient, in wei.
    pub block_value: U256,

    /// Blobs of the payload's blob transactions, one proof each.
    pub blobs_bundle: BlobsBundleV1<P>,

    /// The engine's advice to prefer this payload over a builder's.
    pub should_override_builder: bool,

    /// Requests the payload's transactions triggered.
    pub execution_requests: electra::ExecutionRequests<P>,
}

impl<P: Preset> JsonCodec for GetPayloadResponseV4<P> {
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

/// A Fulu payload the engine built, with its blobs' cell proofs and its requests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetPayloadResponseV5<P: Preset> {
    /// The payload.
    pub execution_payload: deneb::ExecutionPayload<P>,

    /// Value of the payload to the fee recipient, in wei.
    pub block_value: U256,

    /// Blobs of the payload's blob transactions, with cell proofs for PeerDAS.
    pub blobs_bundle: BlobsBundleV2<P>,

    /// The engine's advice to prefer this payload over a builder's.
    pub should_override_builder: bool,

    /// Requests the payload's transactions triggered.
    pub execution_requests: electra::ExecutionRequests<P>,
}

impl<P: Preset> JsonCodec for GetPayloadResponseV5<P> {
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

/// A Gloas or Hstar payload the engine built, with its blobs' cell proofs and its requests.
///
/// Both forks fetch with this version, but each knows its own request types.
/// The requests therefore stay a raw list, checked when decoded for the slot's fork.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetPayloadResponseV6<P: Preset> {
    /// The payload.
    pub execution_payload: gloas::ExecutionPayload<P>,

    /// Value of the payload to the fee recipient, in wei.
    pub block_value: U256,

    /// Blobs of the payload's blob transactions, with cell proofs for PeerDAS.
    pub blobs_bundle: BlobsBundleV2<P>,

    /// The engine's advice to prefer this payload over a builder's.
    pub should_override_builder: bool,

    /// Requests the payload's transactions triggered, as the engine listed them.
    pub execution_requests: RequestsList,
}

impl<P: Preset> JsonCodec for GetPayloadResponseV6<P> {
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

/// A payload the engine built, in the shape of the version that fetched it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GetPayloadResponse<P: Preset> {
    /// The bare Bellatrix payload.
    V1(bellatrix::ExecutionPayload<P>),
    /// A Capella payload.
    V2(GetPayloadResponseV2<P>),
    /// A Deneb payload.
    V3(GetPayloadResponseV3<P>),
    /// An Electra payload.
    V4(GetPayloadResponseV4<P>),
    /// A Fulu payload.
    V5(GetPayloadResponseV5<P>),
    /// A Gloas payload.
    V6(GetPayloadResponseV6<P>),
}

impl<P: Preset> GetPayloadResponse<P> {
    /// Reads the reply of a version.
    ///
    /// # Errors
    ///
    /// Fails when the reply does not have that version's shape, naming where.
    pub fn decode(version: GetPayloadVersion, value: &Json) -> Result<Self, WireError> {
        Ok(match version {
            GetPayloadVersion::V1 => Self::V1(JsonCodec::from_json(value)?),
            GetPayloadVersion::V2 => Self::V2(JsonCodec::from_json(value)?),
            GetPayloadVersion::V3 => Self::V3(JsonCodec::from_json(value)?),
            GetPayloadVersion::V4 => Self::V4(JsonCodec::from_json(value)?),
            GetPayloadVersion::V5 => Self::V5(JsonCodec::from_json(value)?),
            GetPayloadVersion::V6 => Self::V6(JsonCodec::from_json(value)?),
        })
    }

    /// The version whose shape the reply has.
    #[must_use]
    pub const fn version(&self) -> GetPayloadVersion {
        match self {
            Self::V1(_) => GetPayloadVersion::V1,
            Self::V2(_) => GetPayloadVersion::V2,
            Self::V3(_) => GetPayloadVersion::V3,
            Self::V4(_) => GetPayloadVersion::V4,
            Self::V5(_) => GetPayloadVersion::V5,
            Self::V6(_) => GetPayloadVersion::V6,
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;
    use proptest::prelude::*;

    use super::*;
    use crate::wire::{
        blobs::tests::{bundle_v1, bundle_v2},
        payload::tests::{payload_v1, payload_v2, payload_v3, payload_v4},
        requests::tests::{electra_requests, gloas_requests},
    };

    /// Encodes the reply a version holds, as the engine would send it.
    fn encode(response: &GetPayloadResponse<Minimal>) -> Json {
        match response {
            GetPayloadResponse::V1(payload) => payload.to_json(),
            GetPayloadResponse::V2(response) => response.to_json(),
            GetPayloadResponse::V3(response) => response.to_json(),
            GetPayloadResponse::V4(response) => response.to_json(),
            GetPayloadResponse::V5(response) => response.to_json(),
            GetPayloadResponse::V6(response) => response.to_json(),
        }
    }

    /// Any reply of any version.
    fn response() -> impl Strategy<Value = GetPayloadResponse<Minimal>> {
        let value = any::<[u8; 32]>().prop_map(U256);
        prop_oneof![
            payload_v1().prop_map(GetPayloadResponse::V1),
            (payload_v2(), value.clone()).prop_map(|(execution_payload, block_value)| {
                GetPayloadResponse::V2(GetPayloadResponseV2 {
                    execution_payload,
                    block_value,
                })
            }),
            (payload_v3(), value.clone(), bundle_v1(), any::<bool>()).prop_map(
                |(execution_payload, block_value, blobs_bundle, should_override_builder)| {
                    GetPayloadResponse::V3(GetPayloadResponseV3 {
                        execution_payload,
                        block_value,
                        blobs_bundle,
                        should_override_builder,
                    })
                }
            ),
            (
                payload_v3(),
                value.clone(),
                bundle_v1(),
                any::<bool>(),
                electra_requests()
            )
                .prop_map(
                    |(
                        execution_payload,
                        block_value,
                        blobs_bundle,
                        should_override_builder,
                        execution_requests,
                    )| {
                        GetPayloadResponse::V4(GetPayloadResponseV4 {
                            execution_payload,
                            block_value,
                            blobs_bundle,
                            should_override_builder,
                            execution_requests,
                        })
                    }
                ),
            (
                payload_v3(),
                value.clone(),
                bundle_v2(),
                any::<bool>(),
                electra_requests()
            )
                .prop_map(
                    |(
                        execution_payload,
                        block_value,
                        blobs_bundle,
                        should_override_builder,
                        execution_requests,
                    )| {
                        GetPayloadResponse::V5(GetPayloadResponseV5 {
                            execution_payload,
                            block_value,
                            blobs_bundle,
                            should_override_builder,
                            execution_requests,
                        })
                    }
                ),
            (
                payload_v4(),
                value,
                bundle_v2(),
                any::<bool>(),
                gloas_requests().prop_map(|requests| RequestsList::encode(&requests))
            )
                .prop_map(
                    |(
                        execution_payload,
                        block_value,
                        blobs_bundle,
                        should_override_builder,
                        execution_requests,
                    )| {
                        GetPayloadResponse::V6(GetPayloadResponseV6 {
                            execution_payload,
                            block_value,
                            blobs_bundle,
                            should_override_builder,
                            execution_requests,
                        })
                    }
                ),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn every_version_round_trips(response in response()) {
            // The reply decodes back under the version it was built for.
            let value = encode(&response);
            prop_assert_eq!(GetPayloadResponse::decode(response.version(), &value), Ok(response));
        }
    }
}
