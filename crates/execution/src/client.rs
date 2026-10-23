//! The engine API client.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use axiom_http::{Client, ClientConfig, Endpoint, Limits, Method, Request, StatusCode};
use axiom_json::{Json, Limits as JsonLimits};
use axiom_types::{ForkName, Hash32, Preset, VersionedHash, bellatrix::PowBlock};

use crate::{
    Claims, EXECUTION_TIMEOUT, EngineError, EngineMethods, ForkchoiceState, ForkchoiceUpdated,
    ForkchoiceVersion, GetBlobsResponse, GetPayloadResponse, JsonCodec, JwtSecret, NewPayload,
    PayloadAttributes, PayloadId, PayloadStatus, SyncStatus, rpc::Call, wire::Reader,
};

/// Timeout of every lookup-style call, such as engine_getPayload and engine_getBlobs.
///
/// These read data the engine holds already; the spec allows one second.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(1);

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
/// The typed methods take the fork, and the engine methods table picks each version.
/// Calls may run concurrently; each one takes its own pooled connection.
#[derive(Debug)]
pub struct EngineClient {
    /// The HTTP client, bound to the engine's endpoint.
    http: Client,
    /// The shared secret that signs each token.
    secret: JwtSecret,
    /// The next JSON-RPC id; ids only need to be unique per connection, so a counter suffices.
    next_id: AtomicU64,
    /// Factor every call's spec timeout is multiplied by, for engines slower than the spec assumes.
    timeout_multiplier: u32,
}

impl EngineClient {
    /// A client for an engine URL, such as `http://localhost:8551`.
    ///
    /// # Errors
    ///
    /// Fails when the URL is not an http or https URL with a host.
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
            timeout_multiplier: 1,
        }
    }

    /// Multiplies every call's timeout, for an engine on slow hardware.
    ///
    /// A factor of zero is taken as one, so no call times out at once.
    #[must_use]
    pub const fn with_timeout_multiplier(mut self, multiplier: u32) -> Self {
        self.timeout_multiplier = if multiplier == 0 { 1 } else { multiplier };
        self
    }

    /// A spec timeout, scaled by the configured multiplier.
    const fn scaled(&self, timeout: Duration) -> Duration {
        timeout.saturating_mul(self.timeout_multiplier)
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
        let call = Call::new(self.next_id.fetch_add(1, Ordering::Relaxed), method, params);

        // Phase 2: a token issued now, so the engine's 60-second window always holds it.
        let token = self.secret.token(Claims::issued_now());
        let request = Request::new(Method::Post, self.http.endpoint().path())
            .with_header("authorization", format!("Bearer {token}"))
            .with_body("application/json", call.to_bytes());

        // Phase 3: the exchange; the engine answers 200 even for JSON-RPC errors.
        let response = self
            .http
            .send_with_timeout(&request, self.scaled(timeout))
            .await?;
        if response.status != StatusCode::OK {
            return Err(EngineError::Status(response.status));
        }

        // Phase 4: parse under bounds, then unwrap the envelope.
        let limits = JsonLimits {
            max_depth: MAX_RESPONSE_DEPTH,
            max_bytes: MAX_RESPONSE_BYTES,
        };
        let json = Json::parse_with(&response.body, limits).map_err(EngineError::Json)?;
        call.result(json)
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
        Ok(Reader::new(&result).items()?.decode()?)
    }

    /// The methods a fork calls, or the error for a fork that calls none.
    fn methods(fork: ForkName) -> Result<EngineMethods, EngineError> {
        EngineMethods::of(fork).ok_or(EngineError::NoMethod {
            fork,
            family: "engine API",
        })
    }

    /// Hands a payload to the engine for judgement: engine_newPayload.
    ///
    /// The payload's fork picks the version, and its request container fixes the parameters.
    ///
    /// ```text
    ///     V1, V2   [executionPayload]
    ///     V3       [executionPayload, expectedBlobVersionedHashes, parentBeaconBlockRoot]
    ///     V4, V5   [executionPayload, expectedBlobVersionedHashes, parentBeaconBlockRoot,
    ///               executionRequests]
    /// ```
    ///
    /// See `verify_and_notify_new_payload` in the Bellatrix through Gloas specs.
    ///
    /// # Errors
    ///
    /// Fails like any call, and when the status is malformed.
    pub async fn new_payload<P: Preset>(
        &self,
        request: &NewPayload<P>,
    ) -> Result<PayloadStatus, EngineError> {
        let version = Self::methods(request.fork())?.new_payload;
        self.call_typed(version.method(), request.params(), version.timeout())
            .await
    }

    /// Moves the engine's head, and optionally starts a build: engine_forkchoiceUpdated.
    ///
    /// The fork picks the version, which the attributes must match.
    /// Version 4 adds a third parameter, the custody columns; this client sends null.
    /// A null tells the engine the consensus client offers no custody.
    /// See `src/engine/amsterdam.md`.
    ///
    /// # Errors
    ///
    /// Fails like any call, and when the reply is malformed.
    /// Fails before any call when the attributes are of another version than the fork's.
    pub async fn forkchoice_updated<P: Preset>(
        &self,
        fork: ForkName,
        state: &ForkchoiceState,
        attributes: Option<&PayloadAttributes<P>>,
    ) -> Result<ForkchoiceUpdated, EngineError> {
        let version = Self::methods(fork)?.forkchoice_updated;
        if let Some(attributes) = attributes
            && attributes.version() != version
        {
            return Err(EngineError::AttributesVersion {
                fork,
                expected: version,
                actual: attributes.version(),
            });
        }

        // Without attributes the second parameter is an explicit null.
        let attributes = attributes.map_or(Json::Null, PayloadAttributes::to_json);
        let mut params = vec![state.to_json(), attributes];
        if version == ForkchoiceVersion::V4 {
            params.push(Json::Null);
        }
        self.call_typed(version.method(), params, EXECUTION_TIMEOUT)
            .await
    }

    /// Fetches a payload the engine built: engine_getPayload.
    ///
    /// The fork picks the version, and the reply comes back in that version's shape.
    ///
    /// # Errors
    ///
    /// Fails like any call, and when the reply lacks the version's shape.
    /// An unknown id is the engine error -38001.
    pub async fn get_payload<P: Preset>(
        &self,
        fork: ForkName,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<P>, EngineError> {
        let version = Self::methods(fork)?.get_payload;
        let result = self
            .call(version.method(), vec![payload_id.to_json()], LOOKUP_TIMEOUT)
            .await?;
        Ok(GetPayloadResponse::decode(version, &result)?)
    }

    /// Fetches blobs from the engine's pool: engine_getBlobs.
    ///
    /// The fork picks the version: one proof per blob before Fulu, cell proofs from Fulu on.
    ///
    /// # Returns
    ///
    /// The blobs in request order.
    /// Version 1 leaves a gap for each missing blob; version 2 returns nothing when any is missing.
    ///
    /// # Errors
    ///
    /// Fails like any call, and when the reply's length differs from the request's.
    /// Fails before any call when the fork predates blobs.
    pub async fn get_blobs<P: Preset>(
        &self,
        fork: ForkName,
        versioned_hashes: &[VersionedHash],
    ) -> Result<GetBlobsResponse<P>, EngineError> {
        let version = Self::methods(fork)?
            .get_blobs
            .ok_or(EngineError::NoMethod {
                fork,
                family: "engine_getBlobs",
            })?;
        let hashes = Json::Array(versioned_hashes.iter().map(JsonCodec::to_json).collect());
        let result = self
            .call(version.method(), vec![hashes], LOOKUP_TIMEOUT)
            .await?;
        Ok(GetBlobsResponse::decode(
            version,
            &result,
            versioned_hashes.len(),
        )?)
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

    /// Looks up a proof-of-work block by hash: eth_getBlockByHash.
    ///
    /// The merge transition check reads the terminal block and its parent this way.
    /// The engine port serves this method beside the engine methods.
    /// See `get_pow_block` in the Bellatrix fork choice spec.
    ///
    /// # Returns
    ///
    /// The block, or nothing when the engine does not know the hash.
    ///
    /// # Errors
    ///
    /// Fails like any call, when the block is malformed, and when it is another block.
    pub async fn pow_block(&self, hash: Hash32) -> Result<Option<PowBlock>, EngineError> {
        // The second parameter asks for transaction hashes rather than whole transactions.
        let params = vec![hash.to_json(), Json::Bool(false)];
        let block: Option<PowBlock> = self
            .call_typed("eth_getBlockByHash", params, LOOKUP_TIMEOUT)
            .await?;
        match block {
            Some(block) if block.block_hash != hash => Err(EngineError::BlockMismatch {
                requested: hash,
                returned: block.block_hash,
            }),
            found => Ok(found),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_multiplier_scales_every_spec_timeout() {
        let client =
            EngineClient::new("http://127.0.0.1:8551", JwtSecret::new([0x11; 32])).unwrap();

        // Unscaled by default: the spec's eight seconds stay eight.
        assert_eq!(
            client.scaled(Duration::from_secs(8)),
            Duration::from_secs(8)
        );

        // A factor of three gives a slow engine 24 seconds for a new payload.
        let slow = client.with_timeout_multiplier(3);
        assert_eq!(slow.scaled(Duration::from_secs(8)), Duration::from_secs(24));

        // Zero would time every call out at once, so it counts as one.
        let zero = slow.with_timeout_multiplier(0);
        assert_eq!(zero.scaled(LOOKUP_TIMEOUT), LOOKUP_TIMEOUT);
    }
}
