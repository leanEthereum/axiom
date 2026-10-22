//! The beacon API routes a validator client calls, served from the test chain.

use std::{
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
};

use axiom_http::{Method, Request, Response, Router, StatusCode};
use axiom_json::{Data, Json};
use axiom_ssz::Ssz;
use axiom_types::{
    BlsPubkey, BlsSignature, CommitteeIndex, Epoch, ForkName, Minimal, Root, Slot, ValidatorIndex,
    accessors::CoreState,
    altair::{SignedContributionAndProof, SyncCommitteeMessage},
    gloas::{PayloadAttestationMessage, SignedExecutionPayloadEnvelope, SignedProposerPreferences},
};
use axiom_validator::{
    beacon::{
        Duties, Genesis, Liveness, PoolAttestation, SignedAggregate, SignedProposal, SyncStatus,
    },
    json::{ApiJson, Fields},
};

use crate::chain::TestChain;

/// The shared chain every route reads and writes.
pub(crate) type Shared = Arc<Mutex<TestChain>>;

/// A router under construction, whose handlers all reach the chain.
pub(crate) struct Routes {
    /// The routes so far.
    router: Router,
    /// The chain.
    chain: Shared,
}

impl Routes {
    /// Every route a validator client calls.
    pub(crate) fn all(chain: &Shared) -> Router {
        let routes = Self {
            router: Router::new(),
            chain: Arc::clone(chain),
        };
        routes
            .node()
            .duties()
            .production()
            .pools()
            .sync()
            .preparation()
            .router
    }

    /// Adds a route whose handler gets the chain.
    fn add<F, Fut>(self, method: Method, pattern: &str, handler: F) -> Self
    where
        F: Fn(Shared, Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        let chain = Arc::clone(&self.chain);
        let router = self.router.route(method, pattern, move |request| {
            handler(Arc::clone(&chain), request)
        });
        Self {
            router,
            chain: self.chain,
        }
    }

    /// Sync status, genesis, the head, and registry lookups.
    fn node(self) -> Self {
        self.add(Method::Get, "/eth/v1/node/syncing", |chain, _| async move {
            let (_, head_slot) = lock(&chain).head();
            let status = SyncStatus {
                head_slot,
                ..SyncStatus::default()
            };
            data(status.to_json())
        })
        .add(
            Method::Get,
            "/eth/v1/beacon/genesis",
            |chain, _| async move {
                let chain = lock(&chain);
                let beacon = chain.state().beacon();
                let genesis = Genesis {
                    genesis_time: beacon.genesis_time(),
                    genesis_validators_root: beacon.genesis_validators_root(),
                    genesis_fork_version: chain.config().genesis_fork_version,
                };
                drop(chain);
                data(genesis.to_json())
            },
        )
        .add(
            Method::Get,
            "/eth/v1/beacon/blocks/head/root",
            |chain, _| async move {
                let (root, _) = lock(&chain).head();
                data(Json::from([("root", root.to_json())]))
            },
        )
        .add(
            Method::Post,
            "/eth/v1/beacon/states/head/validators",
            |chain, request| async move {
                let ids: Vec<BlsPubkey> = Fields::of(&body(&request))
                    .and_then(|fields| fields.get("ids"))
                    .expect("the request names keys");
                let validators = lock(&chain).validators(&ids);
                data(validators.to_json())
            },
        )
    }

    /// The four kinds of duties.
    fn duties(self) -> Self {
        self.add(
            Method::Get,
            "/eth/v1/validator/duties/proposer/{epoch}",
            |chain, request| async move {
                let epoch = Epoch(number(request.param("epoch")));
                let duties = lock(&chain).proposer_duties(epoch);
                json(&duties.to_json())
            },
        )
        .add(
            Method::Post,
            "/eth/v1/validator/duties/attester/{epoch}",
            |chain, request| async move {
                let epoch = Epoch(number(request.param("epoch")));
                let duties = lock(&chain).attester_duties(epoch, &indices(&request));
                json(&duties.to_json())
            },
        )
        .add(
            Method::Post,
            "/eth/v1/validator/duties/sync/{epoch}",
            |chain, request| async move {
                let epoch = Epoch(number(request.param("epoch")));
                let duties = lock(&chain).sync_duties(epoch, &indices(&request));
                duties.map_or_else(
                    || error(StatusCode::BAD_REQUEST, "no sync committee for that epoch"),
                    |duties| json(&unrooted(duties).to_json()),
                )
            },
        )
        .add(
            Method::Post,
            "/eth/v1/validator/duties/ptc/{epoch}",
            |chain, request| async move {
                let epoch = Epoch(number(request.param("epoch")));
                let duties = lock(&chain).ptc_duties(epoch, &indices(&request));
                duties.map_or_else(
                    || {
                        error(
                            StatusCode::BAD_REQUEST,
                            "no payload timeliness committee then",
                        )
                    },
                    |duties| json(&unrooted(duties).to_json()),
                )
            },
        )
    }

    /// Block production and publication, and payload envelopes.
    fn production(self) -> Self {
        self.add(Method::Get, "/eth/v3/validator/blocks/{slot}", produce)
            .add(Method::Post, "/eth/v4/validator/blocks/{slot}", produce)
            .add(
                Method::Get,
                "/eth/v1/validator/execution_payload_envelopes/{slot}/{root}",
                |chain, request| async move {
                    let root = Root(hex(request.param("root")));
                    let envelope = lock(&chain).envelope(root);
                    envelope.map_or_else(
                        || error(StatusCode::NOT_FOUND, "no envelope for that block"),
                        |envelope| ssz(envelope.encode(), ForkName::Gloas),
                    )
                },
            )
            .add(
                Method::Post,
                "/eth/v2/beacon/blocks",
                |chain, request| async move {
                    let proposal =
                        SignedProposal::<Minimal>::decode(&request.body, fork_of(&request))
                            .expect("the client publishes a valid proposal");
                    let outcome = lock(&chain).publish(&proposal);
                    outcome.map_or_else(
                        |message| error(StatusCode::BAD_REQUEST, &message),
                        |()| ok(),
                    )
                },
            )
            .add(
                Method::Post,
                "/eth/v1/beacon/execution_payload_envelopes",
                |chain, request| async move {
                    let envelope = SignedExecutionPayloadEnvelope::<Minimal>::decode(&request.body)
                        .expect("the client publishes a valid envelope");
                    let outcome = lock(&chain).publish_envelope(&envelope);
                    outcome.map_or_else(
                        |message| error(StatusCode::BAD_REQUEST, &message),
                        |()| ok(),
                    )
                },
            )
    }

    /// Votes and aggregates.
    fn pools(self) -> Self {
        self.add(
            Method::Get,
            "/eth/v1/validator/attestation_data",
            |chain, request| async move {
                let slot = Slot(number(query(&request, "slot")));
                let committee = CommitteeIndex(number(query(&request, "committee_index")));
                let vote = lock(&chain).attestation_data(slot, committee);
                data(vote.to_json())
            },
        )
        .add(
            Method::Post,
            "/eth/v2/beacon/pool/attestations",
            |chain, request| async move {
                let fork = fork_of(&request);
                let votes: Vec<PoolAttestation<Minimal>> = items(&request)
                    .iter()
                    .map(|vote| PoolAttestation::from_json(vote, fork).expect("a vote of the fork"))
                    .collect();
                let mut chain = lock(&chain);
                for vote in votes {
                    chain.add_vote(vote);
                }
                drop(chain);
                ok()
            },
        )
        .add(
            Method::Get,
            "/eth/v2/validator/aggregate_attestation",
            |chain, request| async move {
                let slot = Slot(number(query(&request, "slot")));
                let committee = CommitteeIndex(number(query(&request, "committee_index")));
                let root = Root(hex(query(&request, "attestation_data_root")));
                let (fork, aggregate) = {
                    let chain = lock(&chain);
                    let fork = chain.config().fork_at(slot.epoch::<Minimal>());
                    (fork, chain.aggregate(slot, committee, root, fork))
                };
                aggregate.map_or_else(
                    || error(StatusCode::NOT_FOUND, "no aggregate"),
                    |aggregate| {
                        json(&Json::from([
                            ("version", Json::from(fork.as_str())),
                            ("data", aggregate.to_json()),
                        ]))
                    },
                )
            },
        )
        .add(
            Method::Post,
            "/eth/v2/validator/aggregate_and_proofs",
            |chain, request| async move {
                let fork = fork_of(&request);
                let signed = items(&request);
                for aggregate in &signed {
                    SignedAggregate::<Minimal>::from_json(aggregate, fork)
                        .expect("an aggregate of the fork");
                }
                let count = signed.len();
                lock(&chain).tally.aggregates += count as u64;
                ok()
            },
        )
    }

    /// Sync messages, contributions, and payload votes.
    fn sync(self) -> Self {
        self.add(
            Method::Post,
            "/eth/v1/beacon/pool/sync_committees",
            |chain, request| async move {
                let messages =
                    Vec::<SyncCommitteeMessage>::from_json(&body(&request)).expect("sync messages");
                lock(&chain).add_sync_messages(messages);
                ok()
            },
        )
        .add(
            Method::Get,
            "/eth/v1/validator/sync_committee_contribution",
            |chain, request| async move {
                let slot = Slot(number(query(&request, "slot")));
                let subcommittee = number(query(&request, "subcommittee_index"));
                let root = Root(hex(query(&request, "beacon_block_root")));
                let contribution = lock(&chain).contribution(slot, subcommittee, root);
                contribution.map_or_else(
                    || error(StatusCode::NOT_FOUND, "no contribution"),
                    |contribution| data(contribution.to_json()),
                )
            },
        )
        .add(
            Method::Post,
            "/eth/v1/validator/contribution_and_proofs",
            |chain, request| async move {
                let signed = Vec::<SignedContributionAndProof<Minimal>>::from_json(&body(&request))
                    .expect("signed contributions");
                lock(&chain).tally.contributions += signed.len() as u64;
                ok()
            },
        )
        .add(
            Method::Get,
            "/eth/v1/validator/payload_attestation_data",
            |chain, request| async move {
                let slot = Slot(number(query(&request, "slot")));
                let vote = lock(&chain).payload_attestation_data(slot);
                vote.map_or_else(
                    || Response::new(StatusCode::NO_CONTENT),
                    |vote| data(vote.to_json()),
                )
            },
        )
        .add(
            Method::Post,
            "/eth/v1/beacon/pool/payload_attestations",
            |chain, request| async move {
                let messages = Vec::<PayloadAttestationMessage>::from_json(&body(&request))
                    .expect("payload votes");
                lock(&chain).tally.payload_votes += messages.len() as u64;
                ok()
            },
        )
    }

    /// Subscriptions, preparations, registrations, preferences, and liveness.
    fn preparation(self) -> Self {
        self.add(
            Method::Post,
            "/eth/v1/validator/proposer_preferences",
            |chain, request| async move {
                let preferences = Vec::<SignedProposerPreferences>::from_json(&body(&request))
                    .expect("signed preferences");
                lock(&chain).tally.preferences += preferences.len() as u64;
                ok()
            },
        )
        .add(
            Method::Post,
            "/eth/v1/validator/liveness/{epoch}",
            |_, request| async move {
                // No other instance runs these keys, so no validator is ever seen live.
                let liveness: Vec<Liveness> = indices(&request)
                    .into_iter()
                    .map(|index| Liveness {
                        index,
                        is_live: false,
                    })
                    .collect();
                data(liveness.to_json())
            },
        )
        .add(
            Method::Post,
            "/eth/v1/validator/beacon_committee_subscriptions",
            accept,
        )
        .add(
            Method::Post,
            "/eth/v1/validator/sync_committee_subscriptions",
            accept,
        )
        .add(
            Method::Post,
            "/eth/v1/validator/prepare_beacon_proposer",
            accept,
        )
        .add(Method::Post, "/eth/v1/validator/register_validator", accept)
    }
}

/// Builds the block of a slot, for either produce route.
async fn produce(chain: Shared, request: Request) -> Response {
    let slot = Slot(number(request.param("slot")));
    let reveal = BlsSignature(hex(query(&request, "randao_reveal")));
    let produced = lock(&chain).produce(slot, reveal);
    ssz(produced.encode(), produced.fork())
}

/// Accepts a request and does nothing with it.
async fn accept(_: Shared, _: Request) -> Response {
    ok()
}

/// Locks the chain.
fn lock(chain: &Shared) -> MutexGuard<'_, TestChain> {
    chain
        .lock()
        .expect("no route panics while holding the chain")
}

/// Duties that depend on no root.
const fn unrooted<T>(data: Vec<T>) -> Duties<T> {
    Duties {
        dependent_root: Root::ZERO,
        execution_optimistic: false,
        data,
    }
}

/// A JSON reply wrapping its data.
fn data(inner: Json) -> Response {
    json(&Json::from([("data", inner)]))
}

/// A JSON reply as is.
fn json(body: &Json) -> Response {
    Response::new(StatusCode::OK).with_body("application/json", body.to_string().into_bytes())
}

/// An empty success.
const fn ok() -> Response {
    Response::new(StatusCode::OK)
}

/// An error reply.
fn error(status: StatusCode, message: &str) -> Response {
    let body = Json::from([
        ("code", Json::from(u64::from(status.as_u16()))),
        ("message", Json::from(message)),
    ]);
    Response::new(status).with_body("application/json", body.to_string().into_bytes())
}

/// An SSZ reply tagged with its fork.
fn ssz(bytes: Vec<u8>, fork: ForkName) -> Response {
    Response::new(StatusCode::OK)
        .with_header("eth-consensus-version", fork.as_str())
        .with_header("eth-execution-payload-blinded", "false")
        .with_body("application/octet-stream", bytes)
}

/// A query parameter.
fn query<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .query
        .as_deref()?
        .split('&')
        .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
}

/// A decimal number from the path or the query.
fn number(text: Option<&str>) -> u64 {
    text.expect("the parameter is present")
        .parse()
        .expect("a decimal parameter")
}

/// Fixed-size hex from the path or the query.
fn hex<const N: usize>(text: Option<&str>) -> [u8; N] {
    <[u8; N]>::from_data(text.expect("the parameter is present")).expect("hex of the right size")
}

/// The request body as JSON.
fn body(request: &Request) -> Json {
    Json::parse(&request.body).expect("the client sends JSON")
}

/// The items of a JSON array body.
fn items(request: &Request) -> Vec<Json> {
    body(request)
        .as_array()
        .expect("the client sends an array")
        .to_vec()
}

/// The validator indices a duties request asks for.
fn indices(request: &Request) -> Vec<ValidatorIndex> {
    Vec::<ValidatorIndex>::from_json(&body(request)).expect("an array of indices")
}

/// The fork a request's body follows.
fn fork_of(request: &Request) -> ForkName {
    let name = request
        .headers
        .get("eth-consensus-version")
        .expect("a version header");
    ForkName::from_name(name).expect("a known fork")
}
