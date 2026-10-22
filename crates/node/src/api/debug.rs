//! The debug namespace: whole states and the fork choice's leaves.

use axiom_fork_choice::ExecutionStatus;
use axiom_http::Request;
use axiom_json::Json;
use axiom_types::{Preset, accessors::CoreState};

use super::{
    ApiContext,
    ids::StateId,
    reply::{ApiError, ApiResult, Reply, Routes},
};

/// Routes under `/eth/v2/debug`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DebugRoutes;

impl DebugRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get("/eth/v2/debug/beacon/states/{state_id}", Self::state::<P>)
            .get("/eth/v2/debug/beacon/heads", Self::heads::<P>)
    }

    /// A whole state, as SSZ.
    ///
    /// Only states since finality are held, so older ones answer 404.
    async fn state<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        if !Reply::accepts_ssz(&request) {
            return Err(ApiError::not_acceptable());
        }
        let id: StateId = request
            .param("state_id")
            .ok_or_else(|| ApiError::bad_request("missing state id"))?
            .parse()?;
        context
            .query(move |chain| {
                let root = id
                    .resolve(chain)?
                    .ok_or_else(|| ApiError::not_found("state not found"))?;
                let state = chain
                    .state(&root)
                    .ok_or_else(|| {
                        ApiError::not_found("state is older than finality and not held")
                    })?
                    .beacon();
                let fork = chain.config().fork_at(state.current_epoch());
                Ok(Reply::ssz(state.encode(), fork))
            })
            .await
    }

    /// Every leaf of the fork choice's block tree: the competing chain tips.
    async fn heads<P: Preset>(context: ApiContext<P>, _request: Request) -> ApiResult {
        context
            .query(|chain| {
                let blocks = chain.store().blocks();
                // A leaf is a block nothing builds on yet.
                let leaves: Vec<Json> = blocks
                    .iter()
                    .filter(|(root, _)| blocks.children(root).is_empty())
                    .map(|(root, node)| {
                        Json::from([
                            ("root", Reply::text(&root)),
                            ("slot", Reply::number(node.slot.0)),
                            (
                                "execution_optimistic",
                                (node.status != ExecutionStatus::Valid).into(),
                            ),
                        ])
                    })
                    .collect();
                Ok(Reply::data(Json::from(leaves), None))
            })
            .await
    }
}
