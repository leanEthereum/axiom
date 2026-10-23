//! The beacon node: the pure consensus crates wired to a clock, a database, an engine, and an API.
//!
//! # Overview
//!
//! The chain runs on one thread and owns all consensus state.
//! Async services around it talk to it through a queue.
//!
//! - The clock, the beacon API, and the network feed the chain thread.
//! - The clock sends ticks; the API and the network send requests and messages.
//! - The chain thread emits events, which drive engine updates, logs, and metrics.
//! - The chain thread alone writes the database.

mod api;
mod chain;
mod checkpoint;
mod client_stats;
mod clock;
mod config;
mod engine;
mod error;
mod events;
mod genesis;
mod monitor;
pub(crate) mod network;
mod proposer;
mod publish;
mod race;
mod service;
mod slasher;
mod target_committees;
mod tasks;
mod trusted_setup;

pub use api::BeaconApi;
pub use chain::{
    Chain, ChainDatabase, ChainEvent, ChainHandle, ChainSettings, ChainStopped, ExecutionHead,
    Finality, Head, HistorySegment, HistoryStart, InvalidInterval, ProposerKeys, RawRecord,
    Reconstruction, ReconstructionCursor, SchemaVersion, SegmentContext, SegmentError, SidecarPass,
    SidecarPruning, SnapshotInterval, StateReplay, StorageMode, Submission, TableUsage,
    VerifiedSegment, WeakSubjectivity, WeakSubjectivityError,
};
pub use checkpoint::{CheckpointError, CheckpointServer};
pub use client_stats::{ClientStatsSettings, DEFAULT_PUSH_PERIOD};
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{
    AnchorSource, ApiTls, BuilderClientSettings, BuilderFallback, DatabaseSettings, EngineConfig,
    HistorySettings, NetworkSettings, NodeConfig, ProposerSettings, SlasherSetup,
};
pub use engine::ExecutionLayer;
pub use error::{ChainError, NodeError};
pub use events::{
    ApiEvent, EventHub, EventSender, EventSubscriptions, EventTopic, HubStopped, TopicSet,
    UnknownTopic,
};
pub use genesis::{EmbeddedGenesis, GenesisDownload, GenesisState};
pub use monitor::MonitorSettings;
pub use network::{DiscoverySettings, NodeKey, PortMappingSettings};
pub use proposer::{BlockOrder, ProposerError, ProposerReorgs, ProposerService};
pub use publish::{Proposal, PublishError, Published, Publisher};
pub use service::Node;
pub use trusted_setup::TrustedSetupError;
