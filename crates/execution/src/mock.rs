//! An in-process execution engine for tests.
//!
//! It serves the engine API over real HTTP on a loopback port.
//! Every request must carry a valid token for the shared secret, as a real engine demands.

use std::{
    io,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use axiom_http::{Method, Request, Response, Router, Server, ServerConfig, StatusCode};
use axiom_json::{Json, Object};
use tokio::{sync::oneshot, task::JoinHandle};

use crate::{JwtSecret, RpcError};

/// A scripted engine on a loopback port.
///
/// # Overview
///
/// Tests set a canned reply per method, then point a client at the engine's URL.
/// The engine records each authenticated call, so tests can check the exact parameters sent.
///
/// ```text
///     client --POST + JWT--> mock: verify JWT -> record call -> canned reply
///                                  bad JWT    -> 401, nothing recorded
/// ```
#[derive(Debug)]
pub struct MockEngine {
    /// The base URL clients connect to.
    url: String,
    /// Replies and recorded calls, shared with the server task.
    state: Arc<MockState>,
    /// Fires to shut the server down.
    stop: Option<oneshot::Sender<()>>,
    /// The server task.
    task: JoinHandle<()>,
}

/// One authenticated call the engine received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedCall {
    /// The JSON-RPC method.
    pub method: String,

    /// The parameters, in order.
    pub params: Vec<Json>,

    /// The issued-at of the request's token.
    pub issued_at: u64,
}

/// The canned answer to a method.
#[derive(Clone, Debug)]
enum Reply {
    /// A successful result.
    Result(Json),
    /// A JSON-RPC error object.
    Error(RpcError),
}

/// State shared between the handle and the server task.
#[derive(Debug)]
struct MockState {
    /// The secret every token must be signed with.
    secret: JwtSecret,
    /// Canned replies by method; a later entry for the same method wins.
    replies: Mutex<Vec<(String, Reply)>>,
    /// Calls in arrival order.
    calls: Mutex<Vec<RecordedCall>>,
}

impl MockEngine {
    /// Starts an engine on a free loopback port.
    ///
    /// Must run inside a tokio runtime, which drives the server task.
    ///
    /// # Errors
    ///
    /// Fails when no loopback port can be bound.
    pub async fn start(secret: JwtSecret) -> io::Result<Self> {
        let state = Arc::new(MockState {
            secret,
            replies: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        });

        // Engines answer JSON-RPC on the root path.
        let handler_state = Arc::clone(&state);
        let router = Router::new().route(Method::Post, "/", move |request| {
            let state = Arc::clone(&handler_state);
            async move { state.handle(&request) }
        });

        let server = Server::bind("127.0.0.1:0", router, ServerConfig::default()).await?;
        let url = format!("http://{}", server.local_addr()?);
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(server.serve(async {
            // A dropped sender also stops the server.
            let _ = stopped.await;
        }));

        Ok(Self {
            url,
            state,
            stop: Some(stop),
            task,
        })
    }

    /// The URL to give a client.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Answers every later call of a method with a result.
    pub fn reply(&self, method: &str, result: Json) {
        self.state.set(method, Reply::Result(result));
    }

    /// Answers every later call of a method with an error object.
    pub fn reply_error(&self, method: &str, error: RpcError) {
        self.state.set(method, Reply::Error(error));
    }

    /// The authenticated calls received so far, in arrival order.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        lock(&self.state.calls).clone()
    }

    /// Stops the server and waits for it to drain.
    pub async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = (&mut self.task).await;
    }
}

impl MockState {
    /// Stores a canned reply.
    fn set(&self, method: &str, reply: Reply) {
        lock(&self.replies).push((method.to_owned(), reply));
    }

    /// Serves one HTTP request.
    fn handle(&self, request: &Request) -> Response {
        // Phase 1: authenticate, as an engine must before reading the body.
        let token = request
            .headers
            .get("authorization")
            .and_then(|value| value.strip_prefix("Bearer "));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let claims = match token.map(|token| self.secret.verify(token, now)) {
            Some(Ok(claims)) => claims,
            Some(Err(error)) => return unauthorized(&error.to_string()),
            None => return unauthorized("missing bearer token"),
        };

        // Phase 2: read the JSON-RPC request.
        let Ok(call) = Json::parse(&request.body) else {
            return rpc_reply(
                Json::Null,
                Reply::Error(RpcError::new(RpcError::PARSE_ERROR, "Parse error")),
            );
        };
        let id = call.get("id").cloned().unwrap_or_default();
        let Some(method) = call.get("method").and_then(Json::as_str) else {
            return rpc_reply(
                id,
                Reply::Error(RpcError::new(RpcError::INVALID_REQUEST, "Invalid Request")),
            );
        };
        let params = call
            .get("params")
            .and_then(Json::as_array)
            .map(<[Json]>::to_vec)
            .unwrap_or_default();

        // Phase 3: record the call, then answer from the script.
        lock(&self.calls).push(RecordedCall {
            method: method.to_owned(),
            params,
            issued_at: claims.issued_at,
        });
        let reply = lock(&self.replies)
            .iter()
            .rev()
            .find(|(name, _)| name == method)
            .map_or_else(
                || {
                    Reply::Error(RpcError::new(
                        RpcError::METHOD_NOT_FOUND,
                        "Method not found",
                    ))
                },
                |(_, reply)| reply.clone(),
            );
        rpc_reply(id, reply)
    }
}

/// Locks a mutex, ignoring poisoning: a panicking test thread leaves the data intact.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The 401 a real engine sends for a missing or invalid token.
fn unauthorized(reason: &str) -> Response {
    Response::new(StatusCode::UNAUTHORIZED).with_body("text/plain", reason.as_bytes().to_vec())
}

/// A JSON-RPC response envelope inside a 200 reply.
fn rpc_reply(id: Json, reply: Reply) -> Response {
    let mut envelope = Object::new();
    envelope.insert("jsonrpc", Json::from("2.0"));
    envelope.insert("id", id);
    match reply {
        Reply::Result(result) => envelope.insert("result", result),
        Reply::Error(error) => envelope.insert("error", error.to_json()),
    };
    let body = Json::Object(envelope).to_string().into_bytes();
    Response::new(StatusCode::OK).with_body("application/json", body)
}
