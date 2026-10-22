//! Errors of the chain service and of the node around it.

use std::io;

use axiom_das::CustodyError;
use axiom_execution::{EngineError, JwtError};
use axiom_fork_choice::ForkChoiceError;
use axiom_p2p::swarm::NetworkError;
use axiom_ssz::DecodeError;
use axiom_store::Error as StoreError;
use axiom_telemetry::RegistryError;
use axiom_types::Root;
use thiserror::Error;

/// Why the chain refused an input or could not persist it.
#[derive(Debug, Error)]
pub enum ChainError {
    /// The fork choice refused a block or vote.
    #[error("fork choice: {0}")]
    ForkChoice(#[from] ForkChoiceError),
    /// The database failed to read or write.
    #[error("database: {0}")]
    Database(#[from] StoreError),
    /// Bytes read back from the database do not decode.
    #[error("corrupt {what} in database: {error}")]
    Corrupt {
        /// What was being read.
        what: &'static str,
        /// The decoder's complaint.
        #[source]
        error: DecodeError,
    },
    /// A record the database must hold is missing.
    #[error("database has no {0}")]
    Missing(&'static str),
    /// A block the chain needs has no post-state in the fork choice store.
    #[error("no state for block {0}")]
    MissingState(Root),
    /// A vote does not match the committees it names.
    #[error("invalid vote: {0}")]
    InvalidVote(&'static str),
    /// The chain thread stopped before answering.
    #[error("chain service stopped")]
    Stopped,
}

/// Why the node failed to start or stopped abnormally.
#[derive(Debug, Error)]
pub enum NodeError {
    /// The chain could not be built or resumed.
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    /// A file or socket failed.
    #[error("{context}: {error}")]
    Io {
        /// What was being done.
        context: &'static str,
        /// The operating system's error.
        #[source]
        error: io::Error,
    },
    /// The genesis or checkpoint file does not decode.
    #[error("anchor file does not decode: {0}")]
    Genesis(#[source] DecodeError),
    /// Neither a database to resume nor a genesis state was given.
    #[error("no database to resume and no genesis or checkpoint given")]
    NoAnchor,
    /// The engine endpoint is unusable.
    #[error("execution engine: {0}")]
    Engine(#[source] EngineError),
    /// The JWT secret file does not hold a 32-byte hex secret.
    #[error("JWT secret: {0}")]
    Jwt(#[source] JwtError),
    /// The node's metrics could not be registered.
    #[error("metrics: {0}")]
    Metrics(#[source] RegistryError),
    /// The custody group count is out of range.
    #[error("custody: {0}")]
    Custody(#[source] CustodyError),
    /// The peer-to-peer stack failed to start.
    #[error("network: {0}")]
    Network(#[source] NetworkError),
    /// The chain thread stopped before the node did.
    #[error("chain service stopped unexpectedly")]
    ChainStopped,
}
