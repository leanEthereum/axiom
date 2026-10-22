//! Request parsing, error replies, and the authenticated route table every route shares.

use std::{future::Future, sync::Arc};

use axiom_beacon_json::ApiJsonError;
use axiom_http::{Method, Request, Response, Router, StatusCode};
use axiom_json::{Data, Json};
use axiom_types::BlsPubkey;

use crate::keymanager::auth::ApiToken;

/// Media type of JSON bodies.
const JSON: &str = "application/json";

/// What a route returns: a response, or an error the client is told about.
pub(crate) type ApiResult = Result<Response, ApiError>;

/// An error reply, sent as the keymanager API's error object.
///
/// The body is an object with one message member.
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

    /// The request carries no token.
    pub(crate) fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    /// The request carries a wrong token.
    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    /// The named key is not one this client runs.
    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    /// The client failed in a way the request could not cause.
    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    /// An error with a status and a message.
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// The error as a response.
    pub(crate) fn into_response(self) -> Response {
        Reply::json(
            self.status,
            &Json::from([("message", Json::from(self.message))]),
        )
    }
}

impl From<ApiJsonError> for ApiError {
    fn from(error: ApiJsonError) -> Self {
        Self::bad_request(format!("malformed request body: {error}"))
    }
}

/// Builders for successful replies.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reply;

impl Reply {
    /// A 200 reply whose body wraps a value in a data member.
    pub(crate) fn data(data: Json) -> Response {
        Self::json(StatusCode::OK, &Json::from([("data", data)]))
    }

    /// A JSON reply with an explicit status.
    pub(crate) fn json(status: StatusCode, body: &Json) -> Response {
        Response::new(status).with_body(JSON, body.to_string().into_bytes())
    }

    /// A reply with a status and no body.
    pub(crate) const fn empty(status: StatusCode) -> Response {
        Response::new(status)
    }
}

/// The parts of a request a route reads.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ApiRequest<'a> {
    /// The request.
    request: &'a Request,
}

impl<'a> ApiRequest<'a> {
    /// Wraps a request.
    pub(crate) const fn new(request: &'a Request) -> Self {
        Self { request }
    }

    /// The body, parsed as JSON.
    ///
    /// # Errors
    ///
    /// Fails with 400 when the body is not JSON.
    pub(crate) fn json(self) -> Result<Json, ApiError> {
        Json::parse(&self.request.body)
            .map_err(|error| ApiError::bad_request(format!("request body is not JSON: {error}")))
    }

    /// The public key in the path.
    ///
    /// # Errors
    ///
    /// Fails with 400 when the segment is not 48 bytes of 0x-prefixed hex.
    pub(crate) fn pubkey(self) -> Result<BlsPubkey, ApiError> {
        let text = self.request.param("pubkey").unwrap_or_default();
        <[u8; 48]>::from_data(text)
            .map(BlsPubkey)
            .map_err(|error| ApiError::bad_request(format!("invalid public key {text:?}: {error}")))
    }

    /// The value of a query parameter, when present.
    pub(crate) fn query(self, name: &str) -> Option<&'a str> {
        self.request
            .query
            .as_deref()?
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value)
    }
}

/// A route table whose routes all check the bearer token first.
///
/// A route returns a result; an error becomes the keymanager API's error object.
#[derive(Debug)]
pub(crate) struct Routes {
    /// The routes added so far.
    router: Router,
    /// The token every request must carry.
    token: Arc<ApiToken>,
}

impl Routes {
    /// An empty table behind a token.
    pub(crate) fn new(token: ApiToken) -> Self {
        Self {
            router: Router::new(),
            token: Arc::new(token),
        }
    }

    /// Adds a route whose handler receives a shared state and the request.
    #[must_use]
    pub(crate) fn route<S, F, Fut>(
        self,
        method: Method,
        pattern: &str,
        state: &Arc<S>,
        handler: F,
    ) -> Self
    where
        S: Send + Sync + 'static,
        F: Fn(Arc<S>, Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ApiResult> + Send + 'static,
    {
        let Self { router, token } = self;
        let guard = Arc::clone(&token);
        let state = Arc::clone(state);
        let router = router.route(method, pattern, move |request: Request| {
            // The token is checked before the handler sees any part of the request.
            let reply = guard
                .check(&request)
                .map(|()| handler(Arc::clone(&state), request));
            async move {
                match reply {
                    Ok(reply) => reply.await.unwrap_or_else(ApiError::into_response),
                    Err(refusal) => refusal.into_response(),
                }
            }
        });
        Self { router, token }
    }

    /// The finished router.
    pub(crate) fn finish(self) -> Router {
        self.router
    }
}
