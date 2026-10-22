//! Errors of the chain service and of the node around it.

use std::{io, net::SocketAddr, path::PathBuf};

use axiom_builder_client::BuilderError;
use axiom_das::CustodyError;
use axiom_execution::{EngineError, JwtError};
use axiom_fork_choice::ForkChoiceError;
use axiom_light_client::LightClientError;
use axiom_operation_pool::PoolError;
use axiom_p2p::swarm::NetworkError;
use axiom_slasher::SlasherError;
use axiom_ssz::DecodeError;
use axiom_state_transition::{StateError, TransitionError};
use axiom_store::Error as StoreError;
use axiom_telemetry::RegistryError;
use axiom_types::{CommitteeIndex, ForkName, Root, Slot};
use thiserror::Error;

use crate::chain::{SchemaVersion, WeakSubjectivityError};

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
    /// The operation pool refused an operation.
    #[error("operation pool: {0}")]
    Pool(#[from] PoolError),
    /// The head's fork has no sync committee.
    #[error("the head's {0} state has no sync committee")]
    NoSyncCommittee(ForkName),
    /// The head's state holds no payload timeliness committee for a slot.
    #[error("no payload timeliness committee for slot {0} at the head")]
    NoPayloadCommittee(Slot),
    /// A block the chain needs has no post-state in the fork choice store.
    #[error("no state for block {0}")]
    MissingState(Root),
    /// A vote does not match the committees it names.
    #[error("invalid vote at slot {slot} in committee {committee}: {reason}")]
    InvalidVote {
        /// The slot the vote is for.
        slot: Slot,
        /// The committee the vote names.
        committee: CommitteeIndex,
        /// The rule the vote breaks.
        reason: &'static str,
    },
    /// Light client data could not be derived from a block.
    #[error("light client data: {0}")]
    LightClient(#[from] LightClientError),
    /// The chain thread stopped before answering.
    #[error("chain service stopped")]
    Stopped,
    /// The database was written in a layout this build does not know.
    #[error(
        "database schema version {found} is unknown; this build reads versions 1 to {supported}"
    )]
    UnknownSchema {
        /// The version the database records.
        found: SchemaVersion,
        /// The newest version this build reads.
        supported: SchemaVersion,
    },
    /// A backfill segment was checked against another history start than the stored one.
    #[error(
        "segment extends history from slot {extends}, but the stored history starts at {stored:?}"
    )]
    StaleSegment {
        /// The start slot the segment was checked against.
        extends: Slot,
        /// The stored start slot, if any.
        stored: Option<Slot>,
    },
    /// A finalized block failed to apply while rebuilding a past state.
    #[error("replaying the finalized block at slot {slot}: {source}")]
    Replay {
        /// The block's slot.
        slot: Slot,
        /// Why the block did not apply.
        #[source]
        source: TransitionError,
    },
    /// Empty slots failed to run while rebuilding a past state.
    #[error("running empty slots up to slot {slot}: {source}")]
    ReplaySlots {
        /// The slot the state was carried to.
        slot: Slot,
        /// Why the slots did not run.
        #[source]
        source: StateError,
    },
    /// The chain conflicts with the operator's weak subjectivity checkpoint.
    #[error("weak subjectivity: {0}")]
    WeakSubjectivity(#[from] WeakSubjectivityError),
    /// A genesis state is not the one this chain started from.
    #[error("genesis state root is {actual}, but the chain names {expected}")]
    GenesisMismatch {
        /// The root the chain commits to.
        expected: Root,
        /// The root of the state given.
        actual: Root,
    },
}

/// Why the node failed to start or stopped abnormally.
#[derive(Debug, Error)]
pub enum NodeError {
    /// The chain could not be built or resumed.
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    /// A builder endpoint is not a usable URL.
    #[error("builder {url}: {error}")]
    Builder {
        /// The endpoint as configured.
        url: String,
        /// Why it is unusable, boxed since it is rare and large.
        #[source]
        error: Box<BuilderError>,
    },
    /// An operating system resource, such as a thread or a runtime, failed.
    #[error("{context}: {error}")]
    Io {
        /// What was being done.
        context: &'static str,
        /// The operating system's error.
        #[source]
        error: io::Error,
    },
    /// A file failed to read.
    #[error("{context} {}: {error}", .path.display())]
    File {
        /// What was being done.
        context: &'static str,
        /// The file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        error: io::Error,
    },
    /// A server failed to bind its address.
    #[error("{context} on {address}: {error}")]
    Bind {
        /// What was being done.
        context: &'static str,
        /// The address asked for.
        address: SocketAddr,
        /// The operating system's error.
        #[source]
        error: io::Error,
    },
    /// The genesis or checkpoint file does not decode.
    #[error("anchor file {} does not decode: {source}", .path.display())]
    Genesis {
        /// The anchor file.
        path: PathBuf,
        /// The decoder's complaint.
        #[source]
        source: DecodeError,
    },
    /// Neither a database to resume nor a genesis state was given.
    #[error("no database to resume and no genesis or checkpoint given")]
    NoAnchor,
    /// The slasher could not open its history.
    #[error("slasher: {0}")]
    Slasher(#[source] SlasherError),
    /// The engine endpoint is unusable.
    #[error("execution engine at {url}: {source}")]
    Engine {
        /// The endpoint as configured.
        url: String,
        /// Why the endpoint is unusable.
        #[source]
        source: EngineError,
    },
    /// The JWT secret file does not hold a 32-byte hex secret.
    #[error("JWT secret in {}: {source}", .path.display())]
    Jwt {
        /// The secret file.
        path: PathBuf,
        /// Why the contents are not a secret.
        #[source]
        source: JwtError,
    },
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
