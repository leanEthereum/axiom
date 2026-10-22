//! The engine API client.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axiom_http::{Client, ClientConfig, Endpoint, Limits, Method, Request, StatusCode};
use axiom_json::{Json, Limits as JsonLimits};
use axiom_types::{NewPayloadRequest, Preset, VersionedHash};

use crate::{
    EngineError, ForkchoiceState, ForkchoiceUpdated, GetPayloadResponse, JsonCodec, JwtSecret,
    PayloadAttributes, PayloadId, PayloadStatus, SyncStatus, WireError, WireErrorKind,
    rpc::{self, ResponseError},
    wire::BlobAndProof,
};

/// Timeout of engine_newPayload and engine_forkchoiceUpdated, from `src/engine/cancun.md`.
///
/// Both may execute a block, so the engine gets eight seconds, more than half a slot.
pub const EXECUTION_TIMEOUT: Duration = Duration::from_secs(8);

/// Timeout of every lookup-style call, such as engine_getPayload and engine_getBlobs.
///
/// These read data the engine holds already; the spec allows one second.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(1);

/// Engine methods this client calls, as announced to the engine.
///
/// The list names exactly the Fulu-era versions the typed methods use.
pub const CAPABILITIES: &[&str] = &[
    "engine_newPayloadV4",
    "engine_forkchoiceUpdatedV3",
    "engine_getPayloadV5",
    "engine_getBlobsV2",
];

/// Most bytes accepted in one response.
///
/// A getPayload reply carries its blobs hex-encoded, 256 KiB of text each.
/// 64 MiB holds well over a hundred of them plus a full block of transactions.
const MAX_RESPONSE_BYTES: usize = 64 << 20;

/// Nesting allowed in a response; engine replies nest at most five levels.
const MAX_RESPONSE_DEPTH: usize = 32;

/// A client for the authenticated engine API of one execution client.
///
/// # Overview
///
/// Every call is one HTTP POST carrying a JSON-RPC request.
/// Each request carries a freshly issued JWT, so tokens never go stale between calls.
///
/// ```text
///     POST / HTTP/1.1
///     authorization: Bearer <JWT, iat = now>
///     content-type: application/json
///
///     {"jsonrpc":"2.0","id":N,"method":"engine_...","params":[...]}
/// ```
///
/// The typed methods map onto the Osaka engine API, which the Fulu consensus layer uses.
/// Calls may run concurrently; each one takes its own pooled connection.
#[derive(Debug)]
pub struct EngineClient {
    /// The HTTP client, bound to the engine's endpoint.
    http: Client,
    /// The shared secret that signs each token.
    secret: JwtSecret,
    /// The next JSON-RPC id; ids only need to be unique per connection, so a counter suffices.
    next_id: AtomicU64,
}

impl EngineClient {
    /// A client for an engine URL, such as `http://localhost:8551`.
    ///
    /// # Errors
    ///
    /// Fails when the URL is not a plain http URL with a host.
    pub fn new(url: &str, secret: JwtSecret) -> Result<Self, EngineError> {
        let config = ClientConfig {
            limits: Limits {
                max_body_bytes: MAX_RESPONSE_BYTES,
                ..Limits::DEFAULT
            },
            // Each call sets its own timeout from the spec; this bounds any other call.
            request_timeout: EXECUTION_TIMEOUT,
            ..ClientConfig::default()
        };
        Ok(Self::with_config(Endpoint::parse(url)?, secret, config))
    }

    /// A client with explicit HTTP settings.
    #[must_use]
    pub const fn with_config(endpoint: Endpoint, secret: JwtSecret, config: ClientConfig) -> Self {
        Self {
            http: Client::new(endpoint, config),
            secret,
            next_id: AtomicU64::new(1),
        }
    }

    /// Calls any method and returns its raw result.
    ///
    /// The typed methods build on this; it serves methods they do not cover.
    ///
    /// # Errors
    ///
    /// Fails on transport, HTTP status, JSON, envelope, and engine errors.
    pub async fn call(
        &self,
        method: &str,
        params: Vec<Json>,
        timeout: Duration,
    ) -> Result<Json, EngineError> {
        // Phase 1: the JSON-RPC body.
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = rpc::request(id, method, params).to_string().into_bytes();

        // Phase 2: a token issued now, so the engine's 60-second window always holds it.
        let token = self.secret.token(unix_now());
        let request = Request::new(Method::Post, self.http.endpoint().path())
            .with_header("authorization", format!("Bearer {token}"))
            .with_body("application/json", body);

        // Phase 3: the exchange; the engine answers 200 even for JSON-RPC errors.
        let response = self.http.send_with_timeout(&request, timeout).await?;
        if response.status != StatusCode::OK {
            return Err(EngineError::Status(response.status));
        }

        // Phase 4: parse under bounds, then unwrap the envelope.
        let limits = JsonLimits {
            max_depth: MAX_RESPONSE_DEPTH,
            max_bytes: MAX_RESPONSE_BYTES,
        };
        let json = Json::parse_with(&response.body, limits).map_err(EngineError::Json)?;
        rpc::result(json, id).map_err(|error| match error {
            ResponseError::Envelope(error) => EngineError::Envelope(error),
            ResponseError::Rpc(error) => EngineError::Rpc(error),
        })
    }

    /// Calls a method and decodes its result.
    async fn call_typed<T: JsonCodec>(
        &self,
        method: &str,
        params: Vec<Json>,
        timeout: Duration,
    ) -> Result<T, EngineError> {
        let result = self.call(method, params, timeout).await?;
        Ok(T::from_json(&result)?)
    }

    /// Swaps lists of supported methods with the engine: engine_exchangeCapabilities.
    ///
    /// See `src/engine/common.md`.
    ///
    /// # Errors
    ///
    /// Fails like any call, and when the reply is not a list of strings.
    pub async fn exchange_capabilities(
        &self,
        methods: &[&str],
    ) -> Result<Vec<String>, EngineError> {
        let ours = Json::Array(methods.iter().map(|&method| Json::from(method)).collect());
        let result = self
            .call("engine_exchangeCapabilities", vec![ours], LOOKUP_TIMEOUT)
            .await?;
        // An array of strings; a bad element is located by its index.
        let items = result.as_array().ok_or_else(|| {
            WireError::new(WireErrorKind::Type {
                expected: "array",
                found: result.kind(),
            })
        })?;
        let mut theirs = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            theirs.push(String::from_json(item).map_err(|error| error.at_index(index))?);
        }
        Ok(theirs)
    }

    /// Hands a payload to the engine for validation: engine_newPayloadV4.
    ///
    /// The four parameters follow `src/engine/prague.md`.
    ///
    /// ```text
    ///     [ExecutionPayloadV3, expectedBlobVersionedHashes, parentBeaconBlockRoot, executionRequests]
    /// ```
    ///
    /// The requests list comes from `get_execution_requests_list` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails like any call, and when the status is malformed.
    pub async fn new_payload<P: Preset>(
        &self,
        request: &NewPayloadRequest<P>,
    ) -> Result<PayloadStatus, EngineError> {
        let params = vec![
            request.execution_payload.to_json(),
            request.versioned_hashes.to_json(),
            request.parent_beacon_block_root.to_json(),
            request.execution_requests.to_json(),
        ];
        self.call_typed("engine_newPayloadV4", params, EXECUTION_TIMEOUT)
            .await
    }

    /// Moves the engine's head, and optionally starts a build: engine_forkchoiceUpdatedV3.
    ///
    /// See `src/engine/cancun.md`; Prague and Osaka keep this version.
    ///
    /// # Errors
    ///
    /// Fails like any call, and when the reply is malformed.
    pub async fn forkchoice_updated<P: Preset>(
        &self,
        state: &ForkchoiceState,
        attributes: Option<&PayloadAttributes<P>>,
    ) -> Result<ForkchoiceUpdated, EngineError> {
        // Without attributes the second parameter is an explicit null.
        let attributes = attributes.map_or(Json::Null, JsonCodec::to_json);
        let params = vec![state.to_json(), attributes];
        self.call_typed("engine_forkchoiceUpdatedV3", params, EXECUTION_TIMEOUT)
            .await
    }

    /// Fetches a payload the engine built: engine_getPayloadV5.
    ///
    /// See `src/engine/osaka.md`; the blobs come with cell proofs for PeerDAS.
    ///
    /// # Errors
    ///
    /// Fails like any call; an unknown id is the engine error -38001.
    pub async fn get_payload<P: Preset>(
        &self,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<P>, EngineError> {
        self.call_typed(
            "engine_getPayloadV5",
            vec![payload_id.to_json()],
            LOOKUP_TIMEOUT,
        )
        .await
    }

    /// Fetches blobs from the engine's pool: engine_getBlobsV2.
    ///
    /// See `src/engine/osaka.md`.
    ///
    /// # Returns
    ///
    /// Every blob in request order, or nothing when any one of them is missing.
    ///
    /// # Errors
    ///
    /// Fails like any call, and when the reply's length differs from the request's.
    pub async fn get_blobs<P: Preset>(
        &self,
        versioned_hashes: &[VersionedHash],
    ) -> Result<Option<Vec<BlobAndProof<P>>>, EngineError> {
        let hashes = Json::Array(versioned_hashes.iter().map(JsonCodec::to_json).collect());
        let result = self
            .call("engine_getBlobsV2", vec![hashes], LOOKUP_TIMEOUT)
            .await?;
        // Null is the all-or-nothing answer for any missing blob.
        if result.is_null() {
            return Ok(None);
        }
        let items = result.as_array().ok_or_else(|| {
            WireError::new(WireErrorKind::Type {
                expected: "array or null",
                found: result.kind(),
            })
        })?;
        // One entry per requested hash, in request order.
        if items.len() != versioned_hashes.len() {
            return Err(WireError::new(WireErrorKind::LengthMismatch {
                expected: versioned_hashes.len(),
                actual: items.len(),
            })
            .into());
        }
        let mut blobs = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            blobs.push(BlobAndProof::from_json(item).map_err(|error| error.at_index(index))?);
        }
        Ok(Some(blobs))
    }

    /// The chain id the engine runs: eth_chainId.
    ///
    /// A node checks it at startup against its own configuration.
    ///
    /// # Errors
    ///
    /// Fails like any call, and when the id is not a QUANTITY.
    pub async fn chain_id(&self) -> Result<u64, EngineError> {
        self.call_typed("eth_chainId", Vec::new(), LOOKUP_TIMEOUT)
            .await
    }

    /// Whether the engine is still syncing: eth_syncing.
    ///
    /// # Errors
    ///
    /// Fails like any call, and when the reply is neither false nor a progress object.
    pub async fn syncing(&self) -> Result<SyncStatus, EngineError> {
        self.call_typed("eth_syncing", Vec::new(), LOOKUP_TIMEOUT)
            .await
    }
}

/// Seconds since the Unix epoch on the local clock.
///
/// The engine compares the token's issued-at to its own clock, so both hosts need sane time.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
