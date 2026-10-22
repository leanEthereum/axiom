//! An in-process relay for tests.
//!
//! It serves the builder API over real HTTP on a loopback port.

use std::{
    io,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use axiom_beacon_json::{ApiJson, ApiJsonError, ForkedJson};
use axiom_http::{Method, Request, Response, Router, Server, ServerConfig, StatusCode};
use axiom_json::{Data, Json, Object};
use axiom_types::{
    BlsPubkey, ForkName, Hash32, Preset, Slot,
    bellatrix::SignedValidatorRegistrationV1,
    combined::{SignedBlindedBeaconBlock, SignedBuilderBid},
};
use tokio::{sync::oneshot, task::JoinHandle, time::sleep};

use crate::RevealedPayload;

/// A scripted relay on a loopback port.
///
/// # Overview
///
/// Tests set the bid it offers and the payload it reveals, then point a client at its URL.
/// It records every registration, bid request, and blinded block it receives.
///
/// It checks the shape of each request, not its signatures: tests verify on the client side.
#[derive(Debug)]
pub struct MockRelay {
    /// The base URL clients connect to.
    url: String,
    /// Script and records, shared with the server task.
    state: Arc<MockState>,
    /// Fires to shut the server down.
    stop: Option<oneshot::Sender<()>>,
    /// The server task.
    task: JoinHandle<()>,
}

/// One bid request the relay received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderRequest {
    /// The proposal slot.
    pub slot: Slot,

    /// The parent payload's block hash.
    pub parent_hash: Hash32,

    /// The proposer's key.
    pub pubkey: BlsPubkey,

    /// The proposer's deadline in milliseconds, from the X-Timeout-Ms header.
    pub timeout_ms: Option<u64>,

    /// Whether the request carried a send time in its Date-Milliseconds header.
    pub dated: bool,
}

/// One blinded block the relay received, still as JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Submission {
    /// The fork from the Eth-Consensus-Version header.
    fork: ForkName,
    /// The block's JSON.
    block: Json,
}

/// Script and records, behind one lock each.
#[derive(Debug, Default)]
struct MockState {
    /// Whether the status endpoint answers 200, or 503.
    unhealthy: Mutex<bool>,
    /// The bid offered, as its fork and JSON; none answers 204.
    bid: Mutex<Option<(ForkName, Json)>>,
    /// How long bid requests wait before the answer.
    header_delay: Mutex<Duration>,
    /// The payload revealed, as its fork and JSON; none answers 400.
    reveal: Mutex<Option<(ForkName, Json)>>,
    /// Registrations received, in arrival order.
    registrations: Mutex<Vec<SignedValidatorRegistrationV1>>,
    /// Bid requests received, in arrival order.
    headers: Mutex<Vec<HeaderRequest>>,
    /// Blinded blocks received, in arrival order.
    submissions: Mutex<Vec<Submission>>,
}

impl MockRelay {
    /// Starts a relay on a free loopback port, healthy and without a bid.
    ///
    /// Must run inside a tokio runtime, which drives the server task.
    ///
    /// # Errors
    ///
    /// Fails when no loopback port can be bound.
    pub async fn start() -> io::Result<Self> {
        let state = Arc::new(MockState::default());

        let status = Arc::clone(&state);
        let register = Arc::clone(&state);
        let header = Arc::clone(&state);
        let reveal = Arc::clone(&state);
        let router = Router::new()
            .route(Method::Get, "/eth/v1/builder/status", move |_| {
                let state = Arc::clone(&status);
                async move { state.status() }
            })
            .route(Method::Post, "/eth/v1/builder/validators", move |request| {
                let state = Arc::clone(&register);
                async move { state.register(&request) }
            })
            .route(
                Method::Get,
                "/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}",
                move |request| {
                    let state = Arc::clone(&header);
                    async move { state.header(&request).await }
                },
            )
            .route(
                Method::Post,
                "/eth/v1/builder/blinded_blocks",
                move |request| {
                    let state = Arc::clone(&reveal);
                    async move { state.reveal(&request) }
                },
            );

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

    /// The URL naming a builder key, which pins the client to that key.
    #[must_use]
    pub fn url_with_pubkey(&self, pubkey: &BlsPubkey) -> String {
        self.url
            .replacen("http://", &format!("http://{pubkey}@"), 1)
    }

    /// Makes the status endpoint answer 503 when unhealthy, 200 otherwise.
    pub fn set_healthy(&self, healthy: bool) {
        *MockState::lock(&self.state.unhealthy) = !healthy;
    }

    /// Offers a bid to every later bid request.
    pub fn set_bid<P: Preset>(&self, bid: &SignedBuilderBid<P>) {
        *MockState::lock(&self.state.bid) = Some((bid.fork_name(), bid.to_json()));
    }

    /// Answers every later bid request with 204, no bid.
    pub fn clear_bid(&self) {
        *MockState::lock(&self.state.bid) = None;
    }

    /// Holds every later bid request this long before answering.
    pub fn set_header_delay(&self, delay: Duration) {
        *MockState::lock(&self.state.header_delay) = delay;
    }

    /// Reveals a payload to every later blinded block.
    pub fn set_reveal<P: Preset>(&self, payload: &RevealedPayload<P>) {
        *MockState::lock(&self.state.reveal) = Some((payload.fork_name(), payload.to_json()));
    }

    /// The registrations received so far, in arrival order.
    #[must_use]
    pub fn registrations(&self) -> Vec<SignedValidatorRegistrationV1> {
        MockState::lock(&self.state.registrations).clone()
    }

    /// The bid requests received so far, in arrival order.
    #[must_use]
    pub fn header_requests(&self) -> Vec<HeaderRequest> {
        MockState::lock(&self.state.headers).clone()
    }

    /// The blinded blocks received so far, in arrival order, decoded in their named fork.
    ///
    /// # Errors
    ///
    /// Fails when a block does not decode as its fork's container.
    pub fn blinded_blocks<P: Preset>(
        &self,
    ) -> Result<Vec<SignedBlindedBeaconBlock<P>>, ApiJsonError> {
        MockState::lock(&self.state.submissions)
            .iter()
            .map(|submission| {
                SignedBlindedBeaconBlock::from_json_in(submission.fork, &submission.block)
            })
            .collect()
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
    /// Locks one field, ignoring poisoning: a panicking test thread leaves the data intact.
    fn lock<T>(field: &Mutex<T>) -> MutexGuard<'_, T> {
        field.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The builder API's error body: a code and a message.
    fn error(status: StatusCode, message: &str) -> Response {
        let mut body = Object::new();
        body.insert("code", Json::from(u64::from(status.as_u16())));
        body.insert("message", Json::from(message));
        Response::new(status).with_body(
            "application/json",
            Json::Object(body).to_string().into_bytes(),
        )
    }

    /// A 200 carrying a versioned envelope.
    fn versioned(fork: ForkName, data: Json) -> Response {
        let mut body = Object::new();
        body.insert("version", Json::from(fork.as_str()));
        body.insert("data", data);
        Response::new(StatusCode::OK)
            .with_header("eth-consensus-version", fork.as_str())
            .with_body(
                "application/json",
                Json::Object(body).to_string().into_bytes(),
            )
    }

    /// Serves the status endpoint.
    fn status(&self) -> Response {
        if *Self::lock(&self.unhealthy) {
            Self::error(StatusCode::SERVICE_UNAVAILABLE, "relay unhealthy")
        } else {
            Response::new(StatusCode::OK)
        }
    }

    /// Serves the registration endpoint: a JSON array of signed registrations.
    fn register(&self, request: &Request) -> Response {
        let decoded = Json::parse(&request.body)
            .ok()
            .and_then(|json| json.as_array().map(<[Json]>::to_vec))
            .map(|items| {
                items
                    .iter()
                    .map(SignedValidatorRegistrationV1::from_json)
                    .collect::<Result<Vec<_>, _>>()
            });
        match decoded {
            Some(Ok(registrations)) => {
                Self::lock(&self.registrations).extend(registrations);
                Response::new(StatusCode::OK)
            }
            Some(Err(error)) => Self::error(StatusCode::BAD_REQUEST, &error.to_string()),
            None => Self::error(StatusCode::BAD_REQUEST, "body is not a JSON array"),
        }
    }

    /// Serves the bid endpoint, after the configured delay.
    async fn header(&self, request: &Request) -> Response {
        let slot = request
            .param("slot")
            .and_then(|slot| slot.parse().ok())
            .map(Slot);
        let parent_hash = request
            .param("parent_hash")
            .and_then(|hash| <[u8; 32]>::from_data(hash).ok())
            .map(Hash32);
        let pubkey = request
            .param("pubkey")
            .and_then(|key| <[u8; 48]>::from_data(key).ok())
            .map(BlsPubkey);
        let (Some(slot), Some(parent_hash), Some(pubkey)) = (slot, parent_hash, pubkey) else {
            return Self::error(
                StatusCode::BAD_REQUEST,
                "malformed slot, parent hash, or key",
            );
        };
        Self::lock(&self.headers).push(HeaderRequest {
            slot,
            parent_hash,
            pubkey,
            timeout_ms: request
                .headers
                .get("x-timeout-ms")
                .and_then(|value| value.parse().ok()),
            dated: request.headers.get("date-milliseconds").is_some(),
        });

        let delay = *Self::lock(&self.header_delay);
        if !delay.is_zero() {
            sleep(delay).await;
        }
        let bid = Self::lock(&self.bid).clone();
        match bid {
            Some((fork, bid)) => Self::versioned(fork, bid),
            None => Response::new(StatusCode::NO_CONTENT),
        }
    }

    /// Serves the blinded block endpoint, recording the block and revealing the script's payload.
    fn reveal(&self, request: &Request) -> Response {
        let fork = request
            .headers
            .get("eth-consensus-version")
            .and_then(ForkName::from_name);
        let Some(fork) = fork else {
            return Self::error(
                StatusCode::BAD_REQUEST,
                "missing or unknown consensus version",
            );
        };
        let Ok(block) = Json::parse(&request.body) else {
            return Self::error(StatusCode::BAD_REQUEST, "body is not JSON");
        };
        Self::lock(&self.submissions).push(Submission { fork, block });
        let payload = Self::lock(&self.reveal).clone();
        match payload {
            Some((fork, payload)) => Self::versioned(fork, payload),
            None => Self::error(StatusCode::BAD_REQUEST, "no payload for this block"),
        }
    }
}
