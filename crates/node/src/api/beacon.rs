//! The beacon namespace: genesis, blocks, headers, and state summaries.

use axiom_beacon_json::{ApiJson, api::Genesis};
use axiom_http::{Request, Response, StatusCode};
use axiom_json::Json;
use axiom_ssz::Ssz;
use axiom_types::{ForkName, Preset, accessors::CoreState, gloas::SignedExecutionPayloadEnvelope};
use tracing::warn;

use super::{
    ApiContext,
    ids::{BlockId, StateId},
    query::{Body, Query},
    reply::{ApiError, ApiResult, Reply, Routes},
};
use crate::{ChainStopped, Proposal, PublishError, Published};

/// Routes under `/eth/v1/beacon` and `/eth/v2/beacon`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BeaconRoutes;

impl BeaconRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get("/eth/v1/beacon/genesis", Self::genesis::<P>)
            .get("/eth/v1/beacon/headers/{block_id}", Self::header::<P>)
            .get(
                "/eth/v1/beacon/blocks/{block_id}/root",
                Self::block_root::<P>,
            )
            .get("/eth/v2/beacon/blocks/{block_id}", Self::block::<P>)
            .post("/eth/v2/beacon/blocks", Self::publish::<P>)
            .post(
                "/eth/v1/beacon/execution_payload_envelopes",
                Self::publish_envelope::<P>,
            )
            .get(
                "/eth/v1/beacon/execution_payload_envelopes/{block_id}",
                Self::envelope::<P>,
            )
            .get(
                "/eth/v1/beacon/states/{state_id}/root",
                Self::state_root::<P>,
            )
            .get("/eth/v1/beacon/states/{state_id}/fork", Self::fork::<P>)
            .get(
                "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
                Self::finality_checkpoints::<P>,
            )
    }

    /// Genesis time, validators root, and fork version: what a signer needs to compute domains.
    async fn genesis<P: Preset>(context: ApiContext<P>, _request: Request) -> ApiResult {
        context
            .query(|chain| {
                // Every state carries the genesis fields unchanged, so the head's will do.
                let head = chain.head().root;
                let state = chain
                    .state(&head)
                    .ok_or_else(|| ApiError::not_found("no head state"))?;
                let beacon = state.beacon();
                let genesis = Genesis {
                    genesis_time: beacon.genesis_time(),
                    genesis_validators_root: beacon.genesis_validators_root(),
                    genesis_fork_version: chain.config().genesis_fork_version,
                };
                Ok(Reply::data(genesis.to_json(), None))
            })
            .await
    }

    /// A block's header and whether it is canonical.
    async fn header<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let id = BlockId::from_request(&request)?;
        context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                let header = block.message().header();
                let canonical = chain.canonical_root(header.slot)? == Some(root);
                let data = Json::from([
                    ("root", Reply::text(&root)),
                    ("canonical", canonical.into()),
                    (
                        "header",
                        Json::from([
                            ("message", Reply::header(&header)),
                            ("signature", Reply::text(block.signature())),
                        ]),
                    ),
                ]);
                Ok(Reply::data(
                    data,
                    Some(ApiContext::freshness(chain, root, header.slot)),
                ))
            })
            .await
    }

    /// The root of a block.
    async fn block_root<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let id = BlockId::from_request(&request)?;
        context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                let data = Json::from([("root", Reply::text(&root))]);
                Ok(Reply::data(
                    data,
                    Some(ApiContext::freshness(chain, root, block.slot())),
                ))
            })
            .await
    }

    /// A whole signed block, as SSZ.
    async fn block<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        if !Reply::accepts_ssz(&request) {
            return Err(ApiError::not_acceptable());
        }
        let id = BlockId::from_request(&request)?;
        context
            .query(move |chain| {
                let (_, block) = id.find(chain)?;
                Ok(Reply::ssz(block.encode(), block.fork_name()))
            })
            .await
    }

    /// Publishes a block a validator proposed, with its blobs.
    ///
    /// # Overview
    ///
    /// | outcome                               | status |
    /// |---------------------------------------|--------|
    /// | broadcast and imported                | 200    |
    /// | broadcast, but this node's import failed | 202 |
    /// | body not SSZ                          | 415    |
    /// | malformed, wrong blob data, or invalid | 400   |
    async fn publish<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        if !Reply::sends_ssz(&request) {
            return Err(ApiError::unsupported_media_type());
        }
        let proposal = Self::proposal(&context, &request).await?;
        match context.publisher.publish(proposal).await {
            Ok(Published::Imported(_)) => Ok(Response::new(StatusCode::OK)),
            Ok(Published::BroadcastOnly(error)) => {
                warn!(%error, "published block was broadcast but not imported");
                Ok(Response::new(StatusCode::ACCEPTED))
            }
            Err(PublishError::ChainStopped) => Err(ChainStopped.into()),
            Err(error) => Err(ApiError::bad_request(error.to_string())),
        }
    }

    /// Publishes a signed Gloas payload envelope, as SSZ or JSON.
    ///
    /// # Overview
    ///
    /// Two headers are required: the consensus version, and whether blob data is included.
    /// This node takes the signed envelope alone, so a body announced with blob data is refused.
    ///
    /// The envelope passes the gossip rules before it is broadcast, the default validation level.
    /// The consensus levels need a full import before the broadcast, which this node does not do.
    /// So a request for them is refused rather than silently weakened.
    ///
    /// Statuses follow the block route: 200 imported, 202 broadcast only, 400 invalid.
    /// See `publishExecutionPayloadEnvelope` in the beacon API.
    async fn publish_envelope<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let fork = Self::consensus_version(&request)?;
        if !fork.separates_payloads() {
            return Err(ApiError::bad_request(format!(
                "{fork} blocks carry their payload"
            )));
        }
        match request.headers.get("eth-blob-data-included") {
            Some(value) if value.eq_ignore_ascii_case("false") => {}
            Some(value) if value.eq_ignore_ascii_case("true") => {
                return Err(ApiError::bad_request(
                    "this node takes the signed envelope alone, without blob data",
                ));
            }
            Some(other) => {
                return Err(ApiError::bad_request(format!(
                    "blob data included header is not a boolean: {other}"
                )));
            }
            None => return Err(ApiError::bad_request("missing blob data included header")),
        }
        match Query::of(&request).text("broadcast_validation") {
            None | Some("gossip") => {}
            Some(level @ ("consensus" | "consensus_and_equivocation")) => {
                return Err(ApiError::bad_request(format!(
                    "broadcast validation {level} is not supported; gossip is"
                )));
            }
            Some(other) => {
                return Err(ApiError::bad_request(format!(
                    "unknown broadcast validation: {other}"
                )));
            }
        }
        let envelope = if Reply::sends_ssz(&request) {
            SignedExecutionPayloadEnvelope::<P>::decode(&request.body)
                .map_err(|error| ApiError::bad_request(format!("malformed envelope: {error}")))?
        } else {
            Body(&request).json_item()?
        };
        match context.publisher.publish_envelope(envelope).await {
            Ok(Published::Imported(_)) => Ok(Response::new(StatusCode::OK)),
            Ok(Published::BroadcastOnly(error)) => {
                warn!(%error, "published envelope was broadcast but not imported");
                Ok(Response::new(StatusCode::ACCEPTED))
            }
            Err(PublishError::ChainStopped) => Err(ChainStopped.into()),
            Err(error) => Err(ApiError::bad_request(error.to_string())),
        }
    }

    /// The signed payload envelope of a Gloas block, as JSON or SSZ.
    ///
    /// See `getSignedExecutionPayloadEnvelope` in the beacon API.
    async fn envelope<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let id = BlockId::from_request(&request)?;
        let ssz = Reply::accepts_ssz(&request);
        context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                let envelope = chain
                    .database()
                    .envelope(root)?
                    .ok_or_else(|| ApiError::not_found("execution payload envelope not found"))?;
                if ssz {
                    return Ok(Reply::ssz(envelope.encode(), ForkName::Gloas));
                }
                let freshness = ApiContext::freshness(chain, root, block.slot());
                Ok(Reply::versioned(
                    ForkName::Gloas,
                    envelope.to_json(),
                    Some(freshness),
                ))
            })
            .await
    }

    /// The fork a request's required consensus version header names.
    fn consensus_version(request: &Request) -> Result<ForkName, ApiError> {
        let named = request
            .headers
            .get("eth-consensus-version")
            .ok_or_else(|| ApiError::bad_request("missing consensus version header"))?;
        ForkName::from_name(named)
            .ok_or_else(|| ApiError::bad_request(format!("unknown consensus version: {named}")))
    }

    /// The proposal in a publish request's body, decoded in the fork it names.
    ///
    /// The fork comes from the consensus version header, or else from the clock.
    /// From Deneb to Fulu a block travels with its blobs; any other block travels alone.
    async fn proposal<P: Preset>(
        context: &ApiContext<P>,
        request: &Request,
    ) -> Result<Proposal<P>, ApiError> {
        let named = request.headers.get("eth-consensus-version");
        let fork = match named {
            Some(name) => ForkName::from_name(name).ok_or_else(|| {
                ApiError::bad_request(format!("unknown consensus version: {name}"))
            })?,
            None => {
                context
                    .query(|chain| Ok(chain.config().fork_at(chain.store().current_epoch())))
                    .await?
            }
        };
        let proposal = Proposal::<P>::decode(&request.body, fork)
            .map_err(|error| ApiError::bad_request(format!("malformed {fork} block: {error}")))?;
        // A block must belong to the fork its slot falls in, whatever the header says.
        let slot = proposal.slot();
        let expected = context
            .query(move |chain| Ok(chain.config().fork_at(slot.epoch::<P>())))
            .await?;
        if expected != fork {
            return Err(ApiError::bad_request(format!(
                "block at slot {slot} is in fork {expected}, not {fork}"
            )));
        }
        Ok(proposal)
    }

    /// The root of a state.
    async fn state_root<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let id = StateId::from_request(&request)?;
        context
            .query(move |chain| {
                let (root, block) = id.find_block(chain)?;
                let data = Json::from([("root", Reply::text(&block.message().state_root()))]);
                Ok(Reply::data(
                    data,
                    Some(ApiContext::freshness(chain, root, block.slot())),
                ))
            })
            .await
    }

    /// The fork a state is in.
    async fn fork<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let id = StateId::from_request(&request)?;
        context
            .query(move |chain| {
                let (root, block) = id.find_block(chain)?;
                let fork = ApiContext::held_state(chain, root)?.fork();
                let data = Json::from([
                    ("previous_version", Reply::text(&fork.previous_version)),
                    ("current_version", Reply::text(&fork.current_version)),
                    ("epoch", Reply::number(fork.epoch.0)),
                ]);
                Ok(Reply::data(
                    data,
                    Some(ApiContext::freshness(chain, root, block.slot())),
                ))
            })
            .await
    }

    /// The justified and finalized checkpoints a state records.
    async fn finality_checkpoints<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let id = StateId::from_request(&request)?;
        context
            .query(move |chain| {
                let (root, block) = id.find_block(chain)?;
                let state = ApiContext::held_state(chain, root)?;
                let data = Json::from([
                    (
                        "previous_justified",
                        Reply::checkpoint(state.previous_justified_checkpoint()),
                    ),
                    (
                        "current_justified",
                        Reply::checkpoint(state.current_justified_checkpoint()),
                    ),
                    ("finalized", Reply::checkpoint(state.finalized_checkpoint())),
                ]);
                Ok(Reply::data(
                    data,
                    Some(ApiContext::freshness(chain, root, block.slot())),
                ))
            })
            .await
    }
}
