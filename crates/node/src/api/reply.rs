//! Response shapes and error replies shared by every route.

use std::{fmt, future::Future};

use axiom_beacon_json::{ApiJson, ApiJsonError};
use axiom_http::{Method, Request, Response, Router, StatusCode};
use axiom_json::{Json, Object};
use axiom_ssz::Ssz;
use axiom_types::ForkName;
use tracing::debug;

use super::encoding::{Encoding, JSON, SSZ};
use crate::{ChainError, ChainStopped};

/// One refused item of a list submission: its position and the reason.
pub(crate) type Failure = (usize, String);

/// What a route returns: a response, or an error the client is told about.
pub(crate) type ApiResult = Result<Response, ApiError>;

/// An error reply, sent as the beacon API's error object.
///
/// A list submission names each refused item, as the indexed error object does.
///
/// ```text
///     {"code":404,"message":"block not found"}
///     {"code":400,"message":"some items were refused","failures":[{"index":1,"message":"..."}]}
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApiError {
    /// The HTTP status.
    status: StatusCode,
    /// A sentence for the client.
    message: String,
    /// The refused items of a list submission, empty for any other error.
    failures: Vec<Failure>,
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
    pub(crate) fn not_acceptable(ssz_allowed: bool) -> Self {
        let message = if ssz_allowed {
            "this route serves JSON or SSZ only"
        } else {
            "this route serves JSON only"
        };
        Self::new(StatusCode::NOT_ACCEPTABLE, message)
    }

    /// The request body is in a media type this route does not take.
    pub(crate) fn unsupported_media_type(kind: &str) -> Self {
        Self::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("unsupported body type: {kind}"),
        )
    }

    /// The node cannot answer now, such as while it has no network.
    pub(crate) fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }

    /// Some items of a list submission were refused; the others were accepted.
    ///
    /// See `IndexedErrorMessage` in the beacon API.
    pub(crate) fn indexed(failures: Vec<Failure>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: format!("{} of the submitted items were refused", failures.len()),
            failures,
        }
    }

    /// The node does not implement this optional route.
    pub(crate) fn not_implemented(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_IMPLEMENTED, message)
    }

    /// The node failed in a way the client cannot fix.
    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    /// An error with a status and a message.
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            failures: Vec::new(),
        }
    }

    /// The error as a response.
    pub(crate) fn into_response(self) -> Response {
        let mut body: Object = [
            ("code", Json::from(u64::from(self.status.as_u16()))),
            ("message", Json::from(self.message)),
        ]
        .into_iter()
        .collect();
        if !self.failures.is_empty() {
            let failures = self
                .failures
                .into_iter()
                .map(|(index, message)| {
                    Json::from([
                        ("index", Json::from(index as u64)),
                        ("message", Json::from(message)),
                    ])
                })
                .collect::<Vec<_>>();
            body.insert("failures", Json::Array(failures));
        }
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
        Self::unavailable(error.to_string())
    }
}

impl From<ChainError> for ApiError {
    fn from(error: ChainError) -> Self {
        Self::internal(error.to_string())
    }
}

impl From<ApiJsonError> for ApiError {
    fn from(error: ApiJsonError) -> Self {
        Self::bad_request(format!("malformed body: {error}"))
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
        Self::json(
            StatusCode::OK,
            &Json::from(Self::envelope(None, freshness, data)),
        )
    }

    /// A consensus object in the negotiated encoding, tagged with the fork it follows.
    ///
    /// JSON wraps the object with its fork's name and freshness; SSZ sends the bytes alone.
    /// Both carry the fork in the consensus version field.
    /// Only the encoding asked for is computed.
    pub(crate) fn object(
        encoding: Encoding,
        fork: ForkName,
        freshness: Option<Freshness>,
        json: impl FnOnce() -> Json,
        ssz: impl FnOnce() -> Vec<u8>,
    ) -> Response {
        match encoding {
            Encoding::Ssz => Self::ssz(ssz(), fork),
            Encoding::Json => {
                let body = Self::envelope(Some(fork), freshness, json());
                Self::json(StatusCode::OK, &Json::from(body))
                    .with_header("eth-consensus-version", fork.to_string())
            }
        }
    }

    /// SSZ bytes, tagged with the fork they follow.
    pub(crate) fn ssz(bytes: Vec<u8>, fork: ForkName) -> Response {
        Response::new(StatusCode::OK)
            .with_body(SSZ, bytes)
            .with_header("eth-consensus-version", fork.to_string())
    }

    /// A value of a statically known type, in the negotiated encoding.
    pub(crate) fn typed<T: ApiJson + Ssz>(
        encoding: Encoding,
        fork: ForkName,
        freshness: Option<Freshness>,
        value: &T,
    ) -> Response {
        Self::object(
            encoding,
            fork,
            freshness,
            || value.to_json(),
            || value.encode(),
        )
    }

    /// A sequence of fixed-size values in the negotiated encoding, tagged with a fork.
    ///
    /// Lists and vectors of fixed-size values encode as the values back to back.
    /// So one reply serves any bound, and the progressive lists of later forks too.
    pub(crate) fn sequence<'a, T: ApiJson + Ssz + 'a>(
        encoding: Encoding,
        fork: ForkName,
        freshness: Option<Freshness>,
        items: impl IntoIterator<Item = &'a T>,
    ) -> Response {
        debug_assert!(
            T::FIXED_SIZE.is_some(),
            "only fixed-size values sit back to back"
        );
        let items: Vec<&T> = items.into_iter().collect();
        Self::object(
            encoding,
            fork,
            freshness,
            || Json::Array(items.iter().map(|item| item.to_json()).collect()),
            || {
                let mut bytes = Vec::new();
                for item in &items {
                    item.encode_to(&mut bytes);
                }
                bytes
            },
        )
    }

    /// The top-level object of a reply: version, freshness, then data.
    fn envelope(version: Option<ForkName>, freshness: Option<Freshness>, data: Json) -> Object {
        let mut body = Object::new();
        if let Some(version) = version {
            body.insert("version", Json::from(version.to_string()));
        }
        if let Some(freshness) = freshness {
            body.insert(
                "execution_optimistic",
                Json::from(freshness.execution_optimistic),
            );
            body.insert("finalized", Json::from(freshness.finalized));
        }
        body.insert("data", data);
        body
    }

    /// The reply to a list submission: 200, or 400 naming each refused item.
    ///
    /// Items are handled one by one, so the accepted ones stand even when others fail.
    /// See `IndexedErrorMessage` in the beacon API.
    pub(crate) fn submission(failures: Vec<Failure>) -> ApiResult {
        if failures.is_empty() {
            return Ok(Response::new(StatusCode::OK));
        }
        for (position, message) in &failures {
            debug!(position, %message, "submitted item refused");
        }
        Err(ApiError::indexed(failures))
    }

    /// An empty reply: the request was fine, but there is nothing to answer.
    pub(crate) const fn no_content() -> Response {
        Response::new(StatusCode::NO_CONTENT)
    }

    /// A JSON reply with an explicit status.
    pub(crate) fn json(status: StatusCode, body: &Json) -> Response {
        Response::new(status).with_body(JSON, body.to_string().into_bytes())
    }

    /// A number as the beacon API writes it: a decimal string.
    pub(crate) fn number(value: u64) -> Json {
        Json::from(value.to_string())
    }

    /// Any value through its display form, such as a 0x-prefixed root.
    pub(crate) fn text(value: &impl ToString) -> Json {
        Json::from(value.to_string())
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
    /// Method and pattern of every route added, in order.
    served: Vec<(Method, String)>,
}

impl<S: Clone + Send + Sync + 'static> Routes<S> {
    /// Starts a table over existing routes.
    pub(crate) const fn new(router: Router, state: S) -> Self {
        Self {
            router,
            state,
            served: Vec::new(),
        }
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

    /// Adds a route whose handler builds the whole response itself, such as a stream.
    #[must_use]
    pub(crate) fn raw<F, Fut>(mut self, method: Method, pattern: &str, handler: F) -> Self
    where
        F: Fn(S, Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        let shared = self.state.clone();
        self.router = self.router.route(method, pattern, move |request| {
            handler(shared.clone(), request)
        });
        self.served.push((method, pattern.to_owned()));
        self
    }

    /// The finished router, and the method and pattern of every route it serves.
    pub(crate) fn finish(self) -> (Router, Vec<(Method, String)>) {
        (self.router, self.served)
    }

    /// Adds a route for a method.
    fn add<F, Fut>(self, method: Method, pattern: &str, handler: F) -> Self
    where
        F: Fn(S, Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ApiResult> + Send + 'static,
    {
        self.raw(method, pattern, move |state, request| {
            let reply = handler(state, request);
            async move { reply.await.unwrap_or_else(ApiError::into_response) }
        })
    }
}
