//! Why the node could not produce or publish a proposal.

use axiom_block_production::ProductionError;
use axiom_builder_client::BuilderError;
use axiom_execution::{EngineError, RequestsError};
use axiom_types::{ForkName, Slot};
use thiserror::Error;

use crate::{ChainError, ChainStopped};

/// A proposal the node could not serve.
#[derive(Debug, Error)]
pub enum ProposerError {
    /// The chain thread is gone.
    #[error("chain service stopped")]
    ChainStopped,

    /// The chain could not answer.
    #[error("chain: {0}")]
    Chain(#[from] ChainError),

    /// The block could not be built.
    #[error("production: {0}")]
    Production(#[from] ProductionError),

    /// The fork needs a payload, and no engine is configured.
    #[error("no execution engine is configured to build a payload")]
    NoEngine,

    /// The engine failed.
    #[error("engine: {0}")]
    Engine(#[source] EngineError),

    /// The engine's payload carries a requests list the slot's fork cannot read.
    #[error("engine payload requests: {0}")]
    Requests(#[source] RequestsError),

    /// A blinded block came in, and no builder is configured to reveal it.
    #[error("no builder is configured")]
    NoBuilder,

    /// The builders failed to reveal a payload.
    #[error("builder: {0}")]
    Builder(#[source] BuilderError),

    /// The engine accepted the build but gave it no identifier.
    #[error("the engine started no build for slot {0}")]
    NoBuild(Slot),

    /// The slot is not one the node can propose for now.
    #[error("cannot propose for slot {slot} with the head at slot {head}")]
    SlotOutOfRange {
        /// The slot asked for.
        slot: Slot,
        /// The head's slot.
        head: Slot,
    },

    /// The route serves other forks than the slot's.
    #[error("this route does not produce {0} blocks")]
    WrongRoute(ForkName),
}

impl From<ChainStopped> for ProposerError {
    fn from(_: ChainStopped) -> Self {
        Self::ChainStopped
    }
}
