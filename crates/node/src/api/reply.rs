//! Response shapes and error replies shared by every route.

use std::{fmt, future::Future};

use axiom_http::{Method, Request, Response, Router, StatusCode};
use axiom_json::{Json, Object};
use axiom_types::{
    ForkName,
    phase0::{BeaconBlockHeader, Checkpoint},
};

use crate::{ChainError, ChainStopped};

/// Media type of JSON bodies.
const JSON: &str = "application/json";

/// Media type of SSZ bodies.
const SSZ: &str = "application/octet-stream";

/// What a route returns: a response, or an error the client is told about.
pub(crate) type ApiResult = Result<Response, ApiError>;

/// An error reply, sent as the beacon API's error object.
///
/// ```text
///     {"code":404,"message":"block not found"}
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApiError {
    /// The HTTP status.
    status: StatusCode,
    /// A sentence for the client.
    message: String,
}

impl ApiError {
    /// The request is malformed.
    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    /// The named resource does not exist, or the node no longer holds it.
    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    /// The client accepts no media type this route can produce.
    pub(crate) fn not_acceptable() -> Self {
        Self::new(
            StatusCode::NOT_ACCEPTABLE,
            "only SSZ is served for this route",
        )
    }

    /// The request body is in a media type this route does not take.
    pub(crate) fn unsupported_media_type() -> Self {
        Self::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "only SSZ bodies are accepted",
        )
    }

    /// The node failed in a way the client cannot fix.
    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    /// The node cannot serve the request now, such as without an engine to build with.
    pub(crate) fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }

    /// An error with a status and a message.
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// The error as a response.
    fn into_response(self) -> Response {
        let body: Object = [
            ("code", Json::from(u64::from(self.status.as_u16()))),
            ("message", Json::from(self.message)),
        ]
        .into_iter()
        .collect();
        Response::new(self.status).with_body(JSON, Json::from(body).to_string().into_bytes())
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<ChainStopped> for ApiError {
    fn from(error: ChainStopped) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, error.to_string())
    }
}

impl From<ChainError> for ApiError {
    fn from(error: ChainError) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
    }
}

/// Freshness flags most beacon API replies carry beside their data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Freshness {
    /// Whether the data depends on a payload the engine has not validated.
    pub execution_optimistic: bool,
    /// Whether the data is finalized.
    pub finalized: bool,
}

/// Builders for successful replies.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reply;

impl Reply {
    /// A JSON reply whose data is wrapped in an object.
    ///
    /// ```text
    ///     {"execution_optimistic":false,"finalized":true,"data":{...}}
    /// ```
    pub(crate) fn data(data: Json, freshness: Option<Freshness>) -> Response {
        let mut body = Object::new();
        if let Some(freshness) = freshness {
            body.insert(
                "execution_optimistic",
                Json::from(freshness.execution_optimistic),
            );
            body.insert("finalized", Json::from(freshness.finalized));
        }
        body.insert("data", data);
        Self::json(StatusCode::OK, &Json::from(body))
    }

    /// A JSON reply with an explicit status.
    pub(crate) fn json(status: StatusCode, body: &Json) -> Response {
        Response::new(status).with_body(JSON, body.to_string().into_bytes())
    }

    /// An SSZ reply, tagged with the fork its bytes follow.
    pub(crate) fn ssz(bytes: Vec<u8>, fork: ForkName) -> Response {
        Response::new(StatusCode::OK)
            .with_header("eth-consensus-version", fork.to_string())
            .with_body(SSZ, bytes)
    }

    /// A number as the beacon API writes it: a decimal string.
    pub(crate) fn number(value: u64) -> Json {
        Json::from(value.to_string())
    }

    /// Any value through its display form, such as a 0x-prefixed root.
    pub(crate) fn text(value: &impl ToString) -> Json {
        Json::from(value.to_string())
    }

    /// A header in the beacon API's JSON form.
    pub(crate) fn header(header: &BeaconBlockHeader) -> Json {
        Json::from([
            ("slot", Self::number(header.slot.0)),
            ("proposer_index", Self::number(header.proposer_index.0)),
            ("parent_root", Self::text(&header.parent_root)),
            ("state_root", Self::text(&header.state_root)),
            ("body_root", Self::text(&header.body_root)),
        ])
    }

    /// A checkpoint in the beacon API's JSON form.
    pub(crate) fn checkpoint(checkpoint: Checkpoint) -> Json {
        Json::from([
            ("epoch", Self::number(checkpoint.epoch.0)),
            ("root", Self::text(&checkpoint.root)),
        ])
    }

    /// Whether a request accepts SSZ.
    pub(crate) fn accepts_ssz(request: &Request) -> bool {
        request
            .headers
            .get("accept")
            .is_some_and(|accept| accept.contains(SSZ))
    }

    /// Whether a request's body is SSZ.
    pub(crate) fn sends_ssz(request: &Request) -> bool {
        request
            .headers
            .get("content-type")
            .is_some_and(|kind| kind.starts_with(SSZ))
    }
}

/// A router under construction whose routes all share one piece of state.
///
/// Routes return a result; an error becomes the beacon API's error object.
#[derive(Default)]
pub(crate) struct Routes<S> {
    /// The routes added so far.
    router: Router,
    /// The state each handler receives a clone of.
    state: S,
}

impl<S: Clone + Send + Sync + 'static> Routes<S> {
    /// Starts a table over existing routes.
    pub(crate) const fn new(router: Router, state: S) -> Self {
        Self { router, state }
    }

    /// Adds a GET route.
    #[must_use]
    pub(crate) fn get<F, Fut>(self, pattern: &str, handler: F) -> Self
    where
        F: Fn(S, Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ApiResult> + Send + 'static,
    {
        self.add(Method::Get, pattern, handler)
    }

    /// Adds a POST route.
    #[must_use]
    pub(crate) fn post<F, Fut>(self, pattern: &str, handler: F) -> Self
    where
        F: Fn(S, Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ApiResult> + Send + 'static,
    {
        self.add(Method::Post, pattern, handler)
    }

    /// The finished router.
    pub(crate) fn finish(self) -> Router {
        self.router
    }

    /// Adds a route for a method.
    fn add<F, Fut>(self, method: Method, pattern: &str, handler: F) -> Self
    where
        F: Fn(S, Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ApiResult> + Send + 'static,
    {
        let Self { router, state } = self;
        let shared = state.clone();
        let router = router.route(method, pattern, move |request| {
            // Each request gets its own clone of the state.
            let reply = handler(shared.clone(), request);
            async move { reply.await.unwrap_or_else(ApiError::into_response) }
        });
        Self { router, state }
    }
}
