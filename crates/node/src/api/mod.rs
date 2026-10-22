//! The beacon API: the standard HTTP interface validators and tools use.
//!
//! See the `ethereum/beacon-APIs` repository for every route.
//!
//! Full blocks and states are served as SSZ only.
//! Their JSON forms need a JSON codec for every container, which this node does not carry.

mod beacon;
mod debug;
mod ids;
mod node;
mod reply;

use std::sync::Arc;

use axiom_fork_choice::ExecutionStatus;
use axiom_http::Router;
use axiom_types::{Preset, Root, Slot};

use self::{
    beacon::BeaconRoutes,
    debug::DebugRoutes,
    node::NodeRoutes,
    reply::{ApiError, Freshness, Routes},
};
use crate::{Chain, ChainHandle, Publisher};

/// What every route can reach: the chain and the engine.
#[derive(Debug)]
pub(crate) struct ApiContext<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// Publishes proposed blocks.
    publisher: Arc<Publisher<P>>,
}

impl<P: Preset> Clone for ApiContext<P> {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            publisher: Arc::clone(&self.publisher),
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
    pub fn router<P: Preset>(chain: ChainHandle<P>, publisher: Arc<Publisher<P>>) -> Router {
        let routes = Routes::new(Router::new(), ApiContext { chain, publisher });
        let routes = NodeRoutes::register(routes);
        let routes = BeaconRoutes::register(routes);
        DebugRoutes::register(routes).finish()
    }
}
