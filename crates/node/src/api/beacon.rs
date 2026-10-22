//! The beacon namespace: genesis, blocks, headers, and state summaries.

use axiom_http::{Request, Response, StatusCode};
use axiom_ssz::Ssz;
use axiom_state_transition::State;
use axiom_types::{BeaconState, Preset, Root, SignedBlockContents};
use tracing::warn;

use super::{
    ApiContext,
    ids::{BlockId, StateId},
    reply::{ApiError, ApiResult, Reply, Routes},
};
use crate::{Chain, ChainStopped, PublishError, Published};

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
                Ok(Reply::data(
                    Reply::object([
                        ("genesis_time", Reply::number(beacon.genesis_time)),
                        (
                            "genesis_validators_root",
                            Reply::text(&beacon.genesis_validators_root),
                        ),
                        (
                            "genesis_fork_version",
                            Reply::text(&chain.config().genesis_fork_version),
                        ),
                    ]),
                    None,
                ))
            })
            .await
    }

    /// A block's header and whether it is canonical.
    async fn header<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let id = BlockId::from_request(&request)?;
        context
            .query(move |chain| {
                let (root, block) = id.find(chain)?;
                let message = &block.message;
                let canonical = chain.canonical_root(message.slot)? == Some(root);
                let header = message.header();
                let data = Reply::object([
                    ("root", Reply::text(&root)),
                    ("canonical", canonical.into()),
                    (
                        "header",
                        Reply::object([
                            ("message", Reply::header(&header)),
                            ("signature", Reply::text(&block.signature)),
                        ]),
                    ),
                ]);
                Ok(Reply::data(
                    data,
                    Some(ApiContext::freshness(chain, root, message.slot)),
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
                let data = Reply::object([("root", Reply::text(&root))]);
                Ok(Reply::data(
                    data,
                    Some(ApiContext::freshness(chain, root, block.message.slot)),
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
                let fork = chain.config().fork_at(block.message.slot.epoch::<P>());
                Ok(Reply::ssz(block.encode(), fork))
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
        let contents = SignedBlockContents::<P>::decode(&request.body)
            .map_err(|error| ApiError::bad_request(format!("malformed block contents: {error}")))?;
        match context.publisher.publish(contents).await {
            Ok(Published::Imported(_)) => Ok(Response::new(StatusCode::OK)),
            Ok(Published::BroadcastOnly(error)) => {
                warn!(%error, "published block was broadcast but not imported");
                Ok(Response::new(StatusCode::ACCEPTED))
            }
            Err(PublishError::ChainStopped) => Err(ChainStopped.into()),
            Err(error) => Err(ApiError::bad_request(error.to_string())),
        }
    }

    /// The root of a state.
    async fn state_root<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let id = StateId::from_request(&request)?;
        context
            .query(move |chain| {
                let (root, block) = id.find_block(chain)?;
                let data = Reply::object([("root", Reply::text(&block.message.state_root))]);
                Ok(Reply::data(
                    data,
                    Some(ApiContext::freshness(chain, root, block.message.slot)),
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
                let fork = &Self::held_state(chain, root)?.fork;
                let data = Reply::object([
                    ("previous_version", Reply::text(&fork.previous_version)),
                    ("current_version", Reply::text(&fork.current_version)),
                    ("epoch", Reply::number(fork.epoch.0)),
                ]);
                Ok(Reply::data(
                    data,
                    Some(ApiContext::freshness(chain, root, block.message.slot)),
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
                let state = Self::held_state(chain, root)?;
                let data = Reply::object([
                    (
                        "previous_justified",
                        Reply::checkpoint(state.previous_justified_checkpoint),
                    ),
                    (
                        "current_justified",
                        Reply::checkpoint(state.current_justified_checkpoint),
                    ),
                    ("finalized", Reply::checkpoint(state.finalized_checkpoint)),
                ]);
                Ok(Reply::data(
                    data,
                    Some(ApiContext::freshness(chain, root, block.message.slot)),
                ))
            })
            .await
    }

    /// A post-state the fork choice still holds, or a 404 for one pruned at finality.
    fn held_state<P: Preset>(chain: &Chain<P>, root: Root) -> Result<&BeaconState<P>, ApiError> {
        chain
            .state(&root)
            .map(State::beacon)
            .ok_or_else(|| ApiError::not_found("state is older than finality and not held"))
    }
}
