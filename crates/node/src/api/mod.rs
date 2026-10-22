//! The beacon API: the standard HTTP interface validators and tools use.
//!
//! See the `ethereum/beacon-APIs` repository for every route.
//!
//! Every route speaks JSON, and the routes serving consensus objects also speak SSZ.
//! The JSON form of a consensus object follows from its SSZ schema.

mod beacon;
mod config;
mod debug;
mod duties;
mod encoding;
mod events;
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
mod rewards;
mod states;
mod status;
mod validator;

use std::sync::Arc;

use axiom_fork_choice::ExecutionStatus;
use axiom_http::{Method, Router};
use axiom_types::{ExecutionAddress, Preset, Root, Slot};
use tokio::task;

use self::{
    beacon::BeaconRoutes,
    config::ConfigRoutes,
    debug::DebugRoutes,
    duties::DutyRoutes,
    events::EventRoutes,
    ids::{StateId, StateView},
    light_client::LightClientRoutes,
    liveness::LivenessRoutes,
    node::NodeRoutes,
    pool::PoolRoutes,
    preparation::PreparationRoutes,
    registry::RegistryRoutes,
    reply::{ApiError, Freshness, Routes},
    rewards::RewardsRoutes,
    states::StateRoutes,
    validator::ValidatorRoutes,
};
use crate::{
    Chain, ChainHandle, EventHub, EventSubscriptions, ExecutionLayer, ProposerService, Publisher,
    SystemClock, network::NodeIdentity,
};

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
    /// Opens event streams.
    events: EventSubscriptions,
}

impl<P: Preset> Clone for ApiContext<P> {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            publisher: Arc::clone(&self.publisher),
            proposer: Arc::clone(&self.proposer),
            identity: self.identity.clone(),
            events: self.events.clone(),
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

    /// The state a request names, advanced to the slot it names.
    ///
    /// The chain thread only finds the state; slot processing runs on a blocking worker.
    ///
    /// # Errors
    ///
    /// Fails with a 404 when the node does not hold the state.
    async fn state(&self, id: StateId) -> Result<StateView<P>, ApiError> {
        let (mut view, config) = self
            .query(move |chain| Ok((id.locate(chain)?, chain.config().clone())))
            .await?;
        task::spawn_blocking(move || view.advance(&config).map(|()| view))
            .await
            .map_err(|error| ApiError::internal(format!("state worker failed: {error}")))?
    }

    /// Runs CPU-heavy reply building on a blocking worker, off the async runtime.
    ///
    /// # Errors
    ///
    /// Fails with the work's own error, or a 500 when the worker panics.
    async fn compute<R: Send + 'static>(
        work: impl FnOnce() -> Result<R, ApiError> + Send + 'static,
    ) -> Result<R, ApiError> {
        task::spawn_blocking(work)
            .await
            .map_err(|error| ApiError::internal(format!("worker failed: {error}")))?
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

/// The node's services the beacon API reaches, besides the chain.
#[derive(Debug)]
pub(crate) struct ApiServices<P: Preset> {
    /// Publishes proposed blocks.
    pub publisher: Arc<Publisher<P>>,
    /// Produces blocks for the node's validators.
    pub proposer: Arc<ProposerService<P>>,
    /// How the node presents itself on the network, when it has one.
    pub identity: Option<Arc<NodeIdentity>>,
    /// Opens event streams.
    pub events: EventSubscriptions,
}

/// Builds the beacon API's routes.
#[derive(Clone, Copy, Debug)]
pub struct BeaconApi;

impl BeaconApi {
    /// The router serving every supported route.
    #[must_use]
    pub(crate) fn router<P: Preset>(chain: ChainHandle<P>, services: ApiServices<P>) -> Router {
        let ApiServices {
            publisher,
            proposer,
            identity,
            events,
        } = services;
        Self::build(ApiContext {
            chain,
            publisher,
            proposer,
            identity,
            events,
        })
        .0
    }

    /// The method and path pattern of every route the API serves.
    #[must_use]
    pub fn served<P: Preset>() -> Vec<(Method, String)> {
        // Handlers never run here, so a chain that has stopped is enough.
        let chain = ChainHandle::<P>::stopped();
        let execution = Arc::new(ExecutionLayer::disconnected());
        let publisher = Publisher::new(
            chain.clone(),
            Arc::clone(&execution),
            Arc::new(SystemClock),
            None,
        );
        let proposer = ProposerService::new(chain.clone(), execution, ExecutionAddress::ZERO, None);
        // A hub that never runs: no stream ever opens.
        let (_hub, _sender, events) = EventHub::new();
        let context = ApiContext {
            chain,
            publisher: Arc::new(publisher),
            proposer: Arc::new(proposer),
            identity: None,
            events,
        };
        Self::build(context).1
    }

    /// Registers every namespace's routes, in one place.
    fn build<P: Preset>(context: ApiContext<P>) -> (Router, Vec<(Method, String)>) {
        let routes = Routes::new(Router::new(), context);
        let routes = NodeRoutes::register(routes);
        let routes = BeaconRoutes::register(routes);
        let routes = ConfigRoutes::register(routes);
        let routes = StateRoutes::register(routes);
        let routes = RegistryRoutes::register(routes);
        let routes = LightClientRoutes::register(routes);
        let routes = EventRoutes::register(routes);
        let routes = RewardsRoutes::register(routes);
        let routes = ValidatorRoutes::register(routes);
        let routes = DutyRoutes::register(routes);
        let routes = PreparationRoutes::register(routes);
        let routes = LivenessRoutes::register(routes);
        let routes = PoolRoutes::register(routes);
        DebugRoutes::register(routes).finish()
    }
}
