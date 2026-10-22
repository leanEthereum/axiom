//! Errors of the chain service and of the node around it.

use std::{error::Error, fmt, io};

use axiom_execution::{EngineError, JwtError};
use axiom_fork_choice::ForkChoiceError;
use axiom_ssz::DecodeError;
use axiom_store::Error as StoreError;
use axiom_telemetry::RegistryError;
use axiom_types::Root;

/// Why the chain refused an input or could not persist it.
#[derive(Debug)]
pub enum ChainError {
    /// The fork choice refused a block or vote.
    ForkChoice(ForkChoiceError),
    /// The database failed to read or write.
    Database(StoreError),
    /// Bytes read back from the database do not decode.
    Corrupt {
        /// What was being read.
        what: &'static str,
        /// The decoder's complaint.
        error: DecodeError,
    },
    /// A record the database must hold is missing.
    Missing(&'static str),
    /// A block the chain needs has no post-state in the fork choice store.
    MissingState(Root),
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForkChoice(error) => write!(f, "fork choice: {error}"),
            Self::Database(error) => write!(f, "database: {error}"),
            Self::Corrupt { what, error } => write!(f, "corrupt {what} in database: {error}"),
            Self::Missing(what) => write!(f, "database has no {what}"),
            Self::MissingState(root) => write!(f, "no state for block {root}"),
        }
    }
}

impl Error for ChainError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ForkChoice(error) => Some(error),
            Self::Database(error) => Some(error),
            Self::Corrupt { error, .. } => Some(error),
            Self::Missing(_) | Self::MissingState(_) => None,
        }
    }
}

impl From<ForkChoiceError> for ChainError {
    fn from(error: ForkChoiceError) -> Self {
        Self::ForkChoice(error)
    }
}

impl From<StoreError> for ChainError {
    fn from(error: StoreError) -> Self {
        Self::Database(error)
    }
}

/// Why the node failed to start or stopped abnormally.
#[derive(Debug)]
pub enum NodeError {
    /// The chain could not be built or resumed.
    Chain(ChainError),
    /// A file or socket failed.
    Io {
        /// What was being done.
        context: &'static str,
        /// The operating system's error.
        error: io::Error,
    },
    /// The genesis state file does not decode.
    Genesis(DecodeError),
    /// Neither a database to resume nor a genesis state was given.
    NoAnchor,
    /// The engine endpoint is unusable.
    Engine(EngineError),
    /// The JWT secret file does not hold a 32-byte hex secret.
    Jwt(JwtError),
    /// The node's metrics could not be registered.
    Metrics(RegistryError),
    /// The chain thread stopped before the node did.
    ChainStopped,
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chain(error) => write!(f, "chain: {error}"),
            Self::Io { context, error } => write!(f, "{context}: {error}"),
            Self::Genesis(error) => write!(f, "genesis state does not decode: {error}"),
            Self::NoAnchor => f.write_str("no database to resume and no genesis state given"),
            Self::Engine(error) => write!(f, "execution engine: {error}"),
            Self::Jwt(error) => write!(f, "JWT secret: {error}"),
            Self::Metrics(error) => write!(f, "metrics: {error}"),
            Self::ChainStopped => f.write_str("chain service stopped unexpectedly"),
        }
    }
}

impl Error for NodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Chain(error) => Some(error),
            Self::Io { error, .. } => Some(error),
            Self::Genesis(error) => Some(error),
            Self::Engine(error) => Some(error),
            Self::Jwt(error) => Some(error),
            Self::Metrics(error) => Some(error),
            Self::NoAnchor | Self::ChainStopped => None,
        }
    }
}

impl From<ChainError> for NodeError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}
