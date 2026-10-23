//! The client of one builder API endpoint.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axiom_beacon_json::{ApiJson, ForkedJson};
use axiom_http::{Client, ClientConfig, Endpoint, Limits, Method, Request, Response, StatusCode};
use axiom_json::{Data, Json};
use axiom_types::{
    BlsPubkey, ForkName, Hash32, Preset, Slot,
    bellatrix::SignedValidatorRegistrationV1,
    combined::{SignedBlindedBeaconBlock, SignedBuilderBid},
    gloas::BuilderPreferencesRequest,
};

use crate::{BuilderError, RelayTimeouts, RevealedPayload, versioned::Versioned};

/// The media type of SSZ bodies in the builder API.
const SSZ: &str = "application/octet-stream";

/// The accept header preferring SSZ and admitting JSON, as the builder API's routes offer both.
const PREFER_SSZ: &str = "application/octet-stream;q=1.0,application/json;q=0.9";

/// The media type of JSON bodies.
const JSON: &str = "application/json";

/// A client for the builder API of one relay.
///
/// # Overview
///
/// A relay is configured by URL, optionally naming its builder key as the user name.
/// A configured key pins the relay: a bid signed by any other key is refused.
///
/// ```text
///     https://0x<48-byte builder key>@relay.example
/// ```
///
/// Public relays speak https; a local sidecar usually speaks plain http.
///
/// Bids are asked for in SSZ by preference; a relay may still answer in JSON.
/// A blinded block goes out in SSZ only once the relay's last bid came in SSZ, proving it speaks it.
/// SSZ spares the relay and the node the hex encoding of every blob, doubling their size.
/// See the content negotiation of the getHeader and submitBlindedBlock endpoints.
///
/// Calls may run concurrently; each takes its own pooled connection.
#[derive(Debug)]
pub struct RelayClient {
    /// The HTTP client, bound to the relay's host.
    http: Client,
    /// The URL as configured, for logs.
    url: String,
    /// The path prefix the API routes hang under, without a trailing slash.
    base: String,
    /// The builder key the relay must sign with, when configured.
    pubkey: Option<BlsPubkey>,
    /// Deadline of each call.
    timeouts: RelayTimeouts,
    /// The user agent each request names, when configured.
    user_agent: Option<String>,
    /// Whether SSZ is offered at all; without it every exchange is JSON.
    ssz: bool,
    /// Whether the relay's last bid came in SSZ.
    ssz_answered: AtomicBool,
}

impl RelayClient {
    /// A client for a relay URL, with the default deadlines.
    ///
    /// # Errors
    ///
    /// Fails when the URL is not http or https, or its user name is not a 48-byte hex key.
    pub fn new(url: &str) -> Result<Self, BuilderError> {
        Self::with_timeouts(url, RelayTimeouts::DEFAULT)
    }

    /// A client with explicit deadlines.
    ///
    /// # Errors
    ///
    /// Fails when the URL is not http or https, or its user name is not a 48-byte hex key.
    pub fn with_timeouts(url: &str, timeouts: RelayTimeouts) -> Result<Self, BuilderError> {
        let invalid = || BuilderError::InvalidUrl {
            url: url.to_owned(),
        };

        // The user name sits before an at sign within the authority, per RFC 3986 section 3.2.1.
        let scheme = ["http://", "https://"]
            .into_iter()
            .find(|scheme| {
                url.get(..scheme.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
            })
            .ok_or_else(invalid)?;
        let rest = &url[scheme.len()..];
        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (pubkey, rest) = match rest[..authority_end].split_once('@') {
            Some((user, _)) => {
                let hex = user.strip_prefix("0x").unwrap_or(user);
                let bytes = <[u8; 48]>::from_data(&format!("0x{hex}")).map_err(|_| invalid())?;
                (Some(BlsPubkey(bytes)), &rest[user.len() + 1..])
            }
            None => (None, rest),
        };
        let endpoint = Endpoint::parse(&format!("{scheme}{rest}")).map_err(|_| invalid())?;
        let base = endpoint.path().trim_end_matches('/').to_owned();

        let config = ClientConfig {
            limits: Limits {
                max_body_bytes: Versioned::MAX_BYTES,
                ..Limits::DEFAULT
            },
            // Each call sets its own deadline; this bounds any other.
            request_timeout: timeouts.register,
            ..ClientConfig::default()
        };
        Ok(Self {
            http: Client::new(endpoint, config),
            url: url.to_owned(),
            base,
            pubkey,
            timeouts,
            user_agent: None,
            ssz: true,
            ssz_answered: AtomicBool::new(false),
        })
    }

    /// Exchanges JSON alone, for a relay that mishandles SSZ.
    #[must_use]
    pub const fn json_only(mut self) -> Self {
        self.ssz = false;
        self
    }

    /// Names a user agent on every request, so relay operators can tell clients apart.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// The URL as configured.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The builder key configured for the relay, if any.
    #[must_use]
    pub const fn pubkey(&self) -> Option<&BlsPubkey> {
        self.pubkey.as_ref()
    }

    /// Asks whether the relay is healthy: the status endpoint.
    ///
    /// # Errors
    ///
    /// Fails on a transport error, or any status other than 200.
    pub async fn status(&self) -> Result<(), BuilderError> {
        let request = self.request(Method::Get, "/eth/v1/builder/status");
        let response = self.send(&request, self.timeouts.status).await?;
        Self::expect(&response, StatusCode::OK)
    }

    /// Hands validator registrations to the relay: the registerValidator endpoint.
    ///
    /// The relay checks each signature and keeps the latest registration per validator.
    /// See validator registration processing in the Bellatrix builder spec.
    ///
    /// # Errors
    ///
    /// Fails on a transport error, or any status other than 200.
    pub async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<(), BuilderError> {
        let body = Json::Array(registrations.iter().map(ApiJson::to_json).collect());
        let request = self
            .request(Method::Post, "/eth/v1/builder/validators")
            .with_body("application/json", body.to_string().into_bytes());
        let response = self.send(&request, self.timeouts.register).await?;
        Self::expect(&response, StatusCode::OK)
    }

    /// Hands a proposer's preferences to the builder: the submitBuilderPreferences endpoint.
    ///
    /// The builder checks the signed authentication against the proposer's key.
    /// It answers 202 once it holds the preferences for the slot the authentication names.
    /// See the builder preferences of the Gloas builder spec of the builder API.
    ///
    /// # Errors
    ///
    /// Fails on a transport error, or any status other than 202.
    pub async fn submit_builder_preferences(
        &self,
        proposer: BlsPubkey,
        request: &BuilderPreferencesRequest,
    ) -> Result<(), BuilderError> {
        let target = self.target(&format!("/eth/v1/builder/builder_preferences/{proposer}"));
        let request = Request::new(Method::Post, &target)
            .with_header("eth-consensus-version", ForkName::Gloas.as_str())
            .with_body(
                "application/json",
                request.to_json().to_string().into_bytes(),
            );
        let response = self.send(&request, self.timeouts.register).await?;
        Self::expect(&response, StatusCode::ACCEPTED)
    }

    /// Asks the relay for its best bid: the getHeader endpoint.
    ///
    /// The request states when it was sent and how long the proposer waits.
    /// A relay may hold the bid open until close to that deadline, to raise its value.
    /// See the Date-Milliseconds and X-Timeout-Ms headers of the getHeader endpoint.
    ///
    /// # Returns
    ///
    /// The bid, still unverified, or nothing when the relay answers 204 for no bid.
    ///
    /// # Errors
    ///
    /// Fails before any call when the fork has no builder API.
    /// Fails on a transport error, an unexpected status, or a response of another fork.
    pub async fn header<P: Preset>(
        &self,
        fork: ForkName,
        slot: Slot,
        parent_hash: Hash32,
        pubkey: BlsPubkey,
    ) -> Result<Option<SignedBuilderBid<P>>, BuilderError> {
        if !fork.has_builder_api() {
            return Err(BuilderError::NoBuilderApi { fork });
        }
        let path = format!("/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}");
        let timeout = self.timeouts.header;
        let accept = if self.ssz { PREFER_SSZ } else { JSON };
        let request = self
            .request(Method::Get, &path)
            .with_header("accept", accept)
            .with_header("date-milliseconds", Self::now_millis().to_string())
            .with_header("x-timeout-ms", timeout.as_millis().to_string());
        let response = self.send(&request, timeout).await?;
        match response.status {
            StatusCode::NO_CONTENT => Ok(None),
            StatusCode::OK => {
                let ssz = Self::ssz_body(&response, fork)?;
                self.ssz_answered.store(ssz.is_some(), Ordering::Relaxed);
                let bid = match ssz {
                    Some(bytes) => SignedBuilderBid::decode(bytes, fork)
                        .map_err(BuilderError::Ssz)?
                        .ok_or(BuilderError::NoBuilderApi { fork })?,
                    None => {
                        let versioned = Versioned::parse(&response.body, fork)?;
                        SignedBuilderBid::from_json_in(versioned.fork, &versioned.data)?
                    }
                };
                Ok(Some(bid))
            }
            _ => Err(BuilderError::status(&response)),
        }
    }

    /// Whether a blinded block goes out in SSZ: offered, and the relay's last bid came in it.
    fn sends_ssz(&self) -> bool {
        self.ssz && self.ssz_answered.load(Ordering::Relaxed)
    }

    /// The body of an SSZ response, checked to answer a request of the given fork.
    ///
    /// # Returns
    ///
    /// The body, or nothing when the response is not SSZ.
    ///
    /// # Errors
    ///
    /// Fails when an SSZ response names no fork, an unknown one, or another fork.
    fn ssz_body(response: &Response, expected: ForkName) -> Result<Option<&[u8]>, BuilderError> {
        let is_ssz = response
            .headers
            .get("content-type")
            .is_some_and(|media| media.split(';').next().map(str::trim) == Some(SSZ));
        if !is_ssz {
            return Ok(None);
        }
        let version = response
            .headers
            .get("eth-consensus-version")
            .ok_or(BuilderError::MissingVersionHeader)?;
        let fork = ForkName::from_name(version).ok_or_else(|| BuilderError::UnknownVersion {
            version: version.to_owned(),
        })?;
        if fork != expected {
            return Err(BuilderError::Version {
                expected,
                actual: fork,
            });
        }
        Ok(Some(&response.body))
    }

    /// Hands the signed blinded block to the relay for its payload: the submitBlindedBlock endpoint.
    ///
    /// The first version of the endpoint is used, which returns the payload and its blobs.
    /// The second version answers 202 and publishes the block itself, returning nothing.
    /// The node then could neither check the payload nor publish the block on its own.
    /// The builder API does not ask the beacon node to prefer it, so it is not used.
    ///
    /// # Returns
    ///
    /// The revealed payload, unchecked: completing the block checks it.
    ///
    /// # Errors
    ///
    /// Fails on a transport error, an unexpected status, or a response of another fork.
    pub async fn submit_blinded_block<P: Preset>(
        &self,
        block: &SignedBlindedBeaconBlock<P>,
    ) -> Result<RevealedPayload<P>, BuilderError> {
        let fork = block.fork_name();
        let request = self
            .request(Method::Post, "/eth/v1/builder/blinded_blocks")
            .with_header("eth-consensus-version", fork.as_str());
        let request = if self.sends_ssz() {
            request
                .with_header("accept", PREFER_SSZ)
                .with_body(SSZ, block.encode())
        } else {
            request
                .with_header("accept", JSON)
                .with_body(JSON, block.to_json().to_string().into_bytes())
        };
        let response = self.send(&request, self.timeouts.reveal).await?;
        Self::expect(&response, StatusCode::OK)?;
        if let Some(bytes) = Self::ssz_body(&response, fork)? {
            return RevealedPayload::decode(bytes, fork);
        }
        let versioned = Versioned::parse(&response.body, fork)?;
        Ok(RevealedPayload::from_json_in(
            versioned.fork,
            &versioned.data,
        )?)
    }

    /// An API path under the relay's path prefix.
    fn target(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// A request for an API path, naming the user agent when one is configured.
    fn request(&self, method: Method, path: &str) -> Request {
        let request = Request::new(method, &self.target(path));
        match &self.user_agent {
            Some(agent) => request.with_header("user-agent", agent.clone()),
            None => request,
        }
    }

    /// Sends a request under a deadline.
    async fn send(&self, request: &Request, timeout: Duration) -> Result<Response, BuilderError> {
        Ok(self.http.send_with_timeout(request, timeout).await?)
    }

    /// The error for any status other than the expected one.
    fn expect(response: &Response, status: StatusCode) -> Result<(), BuilderError> {
        if response.status == status {
            Ok(())
        } else {
            Err(BuilderError::status(response))
        }
    }

    /// Unix time in milliseconds, for the Date-Milliseconds header.
    ///
    /// A clock before 1970 sends zero; the header only serves the relay's latency figures.
    fn now_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relay_url_may_name_its_builder_key() {
        // Fixture state: the key 0x0101...01 as user name, a path prefix with a trailing slash.
        let url = format!("http://0x{}@relay.local:18550/api/", "01".repeat(48));
        let client = RelayClient::new(&url).unwrap();
        assert_eq!(client.url(), url);
        assert_eq!(client.pubkey(), Some(&BlsPubkey([1; 48])));
        assert_eq!(
            client.target("/eth/v1/builder/status"),
            "/api/eth/v1/builder/status"
        );

        // A public relay over https keeps its key and reaches port 443.
        let url = format!("https://0x{}@relay.example", "02".repeat(48));
        let client = RelayClient::new(&url).unwrap();
        assert_eq!(client.pubkey(), Some(&BlsPubkey([2; 48])));
        let endpoint = client.http.endpoint();
        assert_eq!(
            (endpoint.is_tls(), endpoint.host(), endpoint.port()),
            (true, "relay.example", 443)
        );

        // Without a user name there is no key, and the path is the root.
        let client = RelayClient::new("http://127.0.0.1:18550").unwrap();
        assert!(!client.http.endpoint().is_tls());
        assert_eq!(client.pubkey(), None);
        assert_eq!(
            client.target("/eth/v1/builder/status"),
            "/eth/v1/builder/status"
        );
    }

    #[test]
    fn requests_name_the_configured_user_agent() {
        // No agent by default; once set, every request carries it.
        let client = RelayClient::new("http://127.0.0.1:18550").unwrap();
        let plain = client.request(Method::Get, "/eth/v1/builder/status");
        assert_eq!(plain.headers.get("user-agent"), None);

        let named = client.with_user_agent("axiom/0.1.0");
        let request = named.request(Method::Get, "/eth/v1/builder/status");
        assert_eq!(request.headers.get("user-agent"), Some("axiom/0.1.0"));
        assert_eq!(request.path, "/eth/v1/builder/status");
    }

    #[test]
    fn bad_relay_urls_are_refused() {
        // Another scheme, a short key, and a key that is not hex.
        for url in [
            "ftp://relay.local".to_owned(),
            format!("http://0x{}@relay.local", "01".repeat(47)),
            format!("http://0x{}@relay.local", "zz".repeat(48)),
        ] {
            let error = RelayClient::new(&url).unwrap_err();
            assert!(
                matches!(&error, BuilderError::InvalidUrl { url: refused } if *refused == url),
                "{url}: {error}"
            );
        }
    }
}
