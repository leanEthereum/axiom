//! The beacon API: the standard HTTP interface validators and tools use.
//!
//! See the `ethereum/beacon-APIs` repository for every route.
//!
//! Full blocks and states are served as SSZ only.
//! Their JSON forms need a JSON codec for every container, which this node does not carry.

mod beacon;
mod debug;
mod duties;
#[cfg(test)]
mod fixture;
mod ids;
mod light_client;
mod liveness;
mod node;
mod pool;
mod preparation;
mod query;
mod registry;
mod reply;
mod validator;

use std::sync::Arc;

use axiom_fork_choice::ExecutionStatus;
use axiom_http::Router;
use axiom_state_transition::State;
use axiom_types::{Preset, Root, Slot, combined::BeaconState};

use self::{
    beacon::BeaconRoutes,
    debug::DebugRoutes,
    duties::DutyRoutes,
    light_client::LightClientRoutes,
    liveness::LivenessRoutes,
    node::NodeRoutes,
    pool::PoolRoutes,
    preparation::PreparationRoutes,
    registry::RegistryRoutes,
    reply::{ApiError, Freshness, Routes},
    validator::ValidatorRoutes,
};
use crate::{Chain, ChainHandle, ProposerService, Publisher, network::NodeIdentity};

/// What every route can reach: the chain and the engine.
#[derive(Debug)]
pub(crate) struct ApiContext<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// Publishes proposed blocks.
    publisher: Arc<Publisher<P>>,
    /// Produces blocks for the node's validators.
    proposer: Arc<ProposerService<P>>,
    /// How the node presents itself on the network, when it has one.
    identity: Option<Arc<NodeIdentity>>,
}

impl<P: Preset> Clone for ApiContext<P> {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            publisher: Arc::clone(&self.publisher),
            proposer: Arc::clone(&self.proposer),
            identity: self.identity.clone(),
        }
    }
}

impl<P: Preset> ApiContext<P> {
    /// Runs a query on the chain thread.
    ///
    /// # Errors
    ///
    /// Fails with the query's own error, or when the chain has stopped.
    async fn query<R: Send + 'static>(
        &self,
        query: impl FnOnce(&mut Chain<P>) -> Result<R, ApiError> + Send + 'static,
    ) -> Result<R, ApiError> {
        self.chain.run(query).await?
    }

    /// The post-state of a block the fork choice still holds, or a 404 for one pruned at finality.
    fn held_state(chain: &Chain<P>, root: Root) -> Result<&BeaconState<P>, ApiError> {
        chain
            .state(&root)
            .map(State::beacon)
            .ok_or_else(|| ApiError::not_found("state is older than finality and not held"))
    }

    /// How fresh data derived from a block is.
    fn freshness(chain: &Chain<P>, root: Root, slot: Slot) -> Freshness {
        let head = chain.head();
        let finalized_slot = chain
            .store()
            .blocks()
            .get(&head.finalized.root)
            .map_or(Slot(0), |node| node.slot);
        Freshness {
            // Blocks no longer in the fork choice are finalized, hence validated.
            execution_optimistic: chain
                .store()
                .blocks()
                .get(&root)
                .is_some_and(|node| node.status != ExecutionStatus::Valid),
            finalized: slot <= finalized_slot,
        }
    }
}

/// Builds the beacon API's routes.
#[derive(Clone, Copy, Debug)]
pub struct BeaconApi;

impl BeaconApi {
    /// The router serving every supported route.
    #[must_use]
    pub(crate) fn router<P: Preset>(
        chain: ChainHandle<P>,
        publisher: Arc<Publisher<P>>,
        proposer: Arc<ProposerService<P>>,
        identity: Option<Arc<NodeIdentity>>,
    ) -> Router {
        let context = ApiContext {
            chain,
            publisher,
            proposer,
            identity,
        };
        let routes = Routes::new(Router::new(), context);
        let routes = NodeRoutes::register(routes);
        let routes = BeaconRoutes::register(routes);
        let routes = RegistryRoutes::register(routes);
        let routes = LightClientRoutes::register(routes);
        let routes = ValidatorRoutes::register(routes);
        let routes = DutyRoutes::register(routes);
        let routes = PreparationRoutes::register(routes);
        let routes = LivenessRoutes::register(routes);
        let routes = PoolRoutes::register(routes);
        DebugRoutes::register(routes).finish()
    }
}
