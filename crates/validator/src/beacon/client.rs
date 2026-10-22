//! One beacon node, reached over HTTP.

use axiom_beacon_json::{ApiJson, Fields};
use axiom_http::{
    Client, ClientConfig, Endpoint, HttpError, Method, Request, Response, StatusCode,
};
use axiom_json::Json;
use axiom_types::ForkName;

use crate::beacon::{BeaconEndpoints, BeaconError, NodeEndpoints, ValidatorEndpoints};

/// Media type of JSON bodies.
pub(crate) const JSON: &str = "application/json";

/// Media type of SSZ bodies.
pub(crate) const SSZ: &str = "application/octet-stream";

/// Header naming the fork a body follows.
pub(crate) const CONSENSUS_VERSION: &str = "eth-consensus-version";

/// A beacon node's API, over one HTTP client.
///
/// The endpoints group by the API's namespaces: node, beacon, and validator.
#[derive(Debug)]
pub struct BeaconClient {
    /// The HTTP client, which pools connections to the node.
    http: Client,
    /// The URL, for logs.
    url: String,
}

impl BeaconClient {
    /// A client for the node at a URL.
    ///
    /// # Errors
    ///
    /// Fails when the URL is not an http or https URL.
    pub fn new(url: &str, config: ClientConfig) -> Result<Self, HttpError> {
        Ok(Self {
            http: Client::new(Endpoint::parse(url)?, config),
            url: url.to_owned(),
        })
    }

    /// The node's URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The node namespace: health and sync status.
    #[must_use]
    pub const fn node(&self) -> NodeEndpoints<'_> {
        NodeEndpoints::new(self)
    }

    /// The beacon namespace: chain data and publishing.
    #[must_use]
    pub const fn beacon(&self) -> BeaconEndpoints<'_> {
        BeaconEndpoints::new(self)
    }

    /// The validator namespace: duties and production.
    #[must_use]
    pub const fn validator(&self) -> ValidatorEndpoints<'_> {
        ValidatorEndpoints::new(self)
    }

    /// Sends a request and turns an error status into an error.
    pub(crate) async fn send(&self, request: Request) -> Result<Response, BeaconError> {
        let response = self.http.send(&request).await?;
        if response.status == StatusCode::NO_CONTENT {
            return Err(BeaconError::NoContent);
        }
        if response.status.is_success() {
            return Ok(response);
        }
        Err(BeaconError::from_reply(response.status, &response.body))
    }

    /// A GET answered in JSON.
    pub(crate) async fn get_json(&self, target: &str) -> Result<Json, BeaconError> {
        let request = Request::new(Method::Get, target).with_header("accept", JSON);
        let response = self.send(request).await?;
        Ok(Json::parse(&response.body)?)
    }

    /// A GET answered in SSZ, with the fork the answer follows.
    pub(crate) async fn get_ssz(&self, target: &str) -> Result<Response, BeaconError> {
        let request = Request::new(Method::Get, target).with_header("accept", SSZ);
        self.send(request).await
    }

    /// A POST of a JSON body, answered in JSON or with nothing.
    pub(crate) async fn post_json(
        &self,
        target: &str,
        body: &Json,
        fork: Option<ForkName>,
    ) -> Result<Option<Json>, BeaconError> {
        let mut request = Request::new(Method::Post, target)
            .with_header("accept", JSON)
            .with_body(JSON, body.to_string().into_bytes());
        if let Some(fork) = fork {
            request = request.with_header(CONSENSUS_VERSION, fork.as_str());
        }
        let response = self.send(request).await?;
        if response.body.is_empty() {
            return Ok(None);
        }
        Ok(Some(Json::parse(&response.body)?))
    }

    /// A POST of an SSZ body, tagged with its fork.
    pub(crate) async fn post_ssz(
        &self,
        request: Request,
        body: Vec<u8>,
        fork: ForkName,
    ) -> Result<Response, BeaconError> {
        let request = request
            .with_header("accept", JSON)
            .with_header(CONSENSUS_VERSION, fork.as_str())
            .with_body(SSZ, body);
        self.send(request).await
    }

    /// The data member of a JSON answer, decoded.
    pub(crate) fn data<T: ApiJson>(json: &Json) -> Result<T, BeaconError> {
        Ok(Fields::of(json)?.required("data")?)
    }

    /// The fork an answer names in its header.
    pub(crate) fn fork_of(response: &Response) -> Result<ForkName, BeaconError> {
        response
            .headers
            .get(CONSENSUS_VERSION)
            .and_then(|name| ForkName::from_name(&name.to_ascii_lowercase()))
            .ok_or(BeaconError::Header(CONSENSUS_VERSION))
    }
}
