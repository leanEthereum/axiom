//! The beacon node: the pure consensus crates wired to a clock, a database, an engine, and an API.
//!
//! # Overview
//!
//! The chain runs on one thread and owns all consensus state.
//! Async services around it talk to it through a queue.
//!
//! ```text
//!     clock ──ticks──┐
//!     beacon api ────┼──> chain thread ──events──> engine updates, logs, metrics
//!     network ───────┘         │
//!                              └──> database
//! ```

mod api;
mod chain;
mod clock;
mod config;
mod engine;
mod error;
pub(crate) mod network;
mod publish;
mod race;
mod service;
mod tasks;

pub use api::BeaconApi;
pub use chain::{
    Chain, ChainDatabase, ChainEvent, ChainHandle, ChainStopped, ExecutionHead, Head, Submission,
};
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{AnchorSource, EngineConfig, NetworkSettings, NodeConfig};
pub use engine::ExecutionLayer;
pub use error::{ChainError, NodeError};
pub use network::{DiscoverySettings, NodeKey};
pub use publish::{PublishError, Published, Publisher};
pub use service::Node;
