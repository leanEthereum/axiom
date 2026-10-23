//! An in-process relay for tests.
//!
//! It serves the builder API over real HTTP on a loopback port.

use std::{
    io,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use axiom_beacon_json::{ApiJson, ForkedJson};
use axiom_http::{Method, Request, Response, Router, Server, ServerConfig, StatusCode};
use axiom_json::{Data, Json, Object};
use axiom_types::{
    BlsPubkey, ForkName, Hash32, Preset, Slot,
    bellatrix::SignedValidatorRegistrationV1,
    combined::{SignedBlindedBeaconBlock, SignedBuilderBid},
    gloas::BuilderPreferencesRequest,
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

/// One blinded block the relay received, still encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Submission {
    /// The fork from the Eth-Consensus-Version header.
    fork: ForkName,
    /// The block as it came.
    block: Encoded,
}

/// A body in either encoding the builder API allows.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Encoded {
    /// A JSON value.
    Json(Json),
    /// SSZ bytes.
    Ssz(Vec<u8>),
}

/// A scripted answer: its fork and both of its encodings.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Scripted {
    /// The fork.
    fork: ForkName,
    /// The JSON data.
    json: Json,
    /// The SSZ bytes.
    ssz: Vec<u8>,
}

/// Script and records, behind one lock each.
#[derive(Debug, Default)]
struct MockState {
    /// Whether the status endpoint answers 200, or 503.
    unhealthy: Mutex<bool>,
    /// Whether the relay answers JSON alone, whatever the client prefers.
    json_only: Mutex<bool>,
    /// The bid offered; none answers 204.
    bid: Mutex<Option<Scripted>>,
    /// How long bid requests wait before the answer.
    header_delay: Mutex<Duration>,
    /// The payload revealed; none answers 400.
    reveal: Mutex<Option<Scripted>>,
    /// Registrations received, in arrival order.
    registrations: Mutex<Vec<SignedValidatorRegistrationV1>>,
    /// Bid requests received, in arrival order.
    headers: Mutex<Vec<HeaderRequest>>,
    /// Blinded blocks received, in arrival order.
    submissions: Mutex<Vec<Submission>>,
    /// Builder preferences received, with their proposer, in arrival order.
    preferences: Mutex<Vec<(BlsPubkey, BuilderPreferencesRequest)>>,
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
        let preferences = Arc::clone(&state);
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
            )
            .route(
                Method::Post,
                "/eth/v1/builder/builder_preferences/{proposer_pubkey}",
                move |request| {
                    let state = Arc::clone(&preferences);
                    async move { state.preferences(&request) }
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

    /// Answers in JSON alone, as a relay without SSZ support does; by default SSZ is offered.
    pub fn set_json_only(&self, json_only: bool) {
        *MockState::lock(&self.state.json_only) = json_only;
    }

    /// Offers a bid to every later bid request.
    pub fn set_bid<P: Preset>(&self, bid: &SignedBuilderBid<P>) {
        *MockState::lock(&self.state.bid) = Some(Scripted {
            fork: bid.fork_name(),
            json: bid.to_json(),
            ssz: bid.encode(),
        });
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
        *MockState::lock(&self.state.reveal) = Some(Scripted {
            fork: payload.fork_name(),
            json: payload.to_json(),
            ssz: payload.encode(),
        });
    }

    /// Whether each blinded block received came in SSZ, in arrival order.
    #[must_use]
    pub fn blinded_blocks_in_ssz(&self) -> Vec<bool> {
        MockState::lock(&self.state.submissions)
            .iter()
            .map(|submission| matches!(submission.block, Encoded::Ssz(_)))
            .collect()
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
    pub fn blinded_blocks<P: Preset>(&self) -> Result<Vec<SignedBlindedBeaconBlock<P>>, String> {
        MockState::lock(&self.state.submissions)
            .iter()
            .map(|submission| match &submission.block {
                Encoded::Json(block) => {
                    SignedBlindedBeaconBlock::from_json_in(submission.fork, block)
                        .map_err(|error| error.to_string())
                }
                Encoded::Ssz(bytes) => SignedBlindedBeaconBlock::decode(bytes, submission.fork)
                    .map_err(|error| error.to_string()),
            })
            .collect()
    }

    /// The builder preferences received, with the proposer each names, in arrival order.
    #[must_use]
    pub fn builder_preferences(&self) -> Vec<(BlsPubkey, BuilderPreferencesRequest)> {
        MockState::lock(&self.state.preferences).clone()
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

    /// A 200 carrying a scripted answer, in SSZ when the request accepts it and the relay speaks it.
    fn answer(&self, request: &Request, scripted: Scripted) -> Response {
        let accepts_ssz = request
            .headers
            .get("accept")
            .is_some_and(|accept| accept.contains("application/octet-stream"));
        let response = Response::new(StatusCode::OK)
            .with_header("eth-consensus-version", scripted.fork.as_str());
        if accepts_ssz && !*Self::lock(&self.json_only) {
            return response.with_body("application/octet-stream", scripted.ssz);
        }
        let mut body = Object::new();
        body.insert("version", Json::from(scripted.fork.as_str()));
        body.insert("data", scripted.json);
        response.with_body(
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

    /// Serves the builder preferences endpoint: one JSON request for the proposer in the path.
    fn preferences(&self, request: &Request) -> Response {
        let proposer = request
            .param("proposer_pubkey")
            .and_then(|key| <[u8; 48]>::from_data(key).ok())
            .map(BlsPubkey);
        let Some(proposer) = proposer else {
            return Self::error(StatusCode::BAD_REQUEST, "malformed proposer key");
        };
        if request.headers.get("eth-consensus-version") != Some(ForkName::Gloas.as_str()) {
            return Self::error(
                StatusCode::BAD_REQUEST,
                "missing or wrong consensus version",
            );
        }
        let decoded = Json::parse(&request.body)
            .map_err(|error| error.to_string())
            .and_then(|json| {
                BuilderPreferencesRequest::from_json(&json).map_err(|error| error.to_string())
            });
        match decoded {
            Ok(preferences) => {
                Self::lock(&self.preferences).push((proposer, preferences));
                Response::new(StatusCode::ACCEPTED)
            }
            Err(error) => Self::error(StatusCode::BAD_REQUEST, &error),
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
            Some(bid) => self.answer(request, bid),
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
        let block = if request.headers.get("content-type") == Some("application/octet-stream") {
            if *Self::lock(&self.json_only) {
                return Self::error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "SSZ is not supported");
            }
            Encoded::Ssz(request.body.clone())
        } else {
            let Ok(block) = Json::parse(&request.body) else {
                return Self::error(StatusCode::BAD_REQUEST, "body is not JSON");
            };
            Encoded::Json(block)
        };
        Self::lock(&self.submissions).push(Submission { fork, block });
        let payload = Self::lock(&self.reveal).clone();
        match payload {
            Some(payload) => self.answer(request, payload),
            None => Self::error(StatusCode::BAD_REQUEST, "no payload for this block"),
        }
    }
}
