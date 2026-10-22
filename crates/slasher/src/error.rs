//! Why a slasher cannot start, read its history, or build evidence.

use axiom_snappy::SnappyError;
use axiom_ssz::DecodeError;
use axiom_types::{Epoch, ForkName};
use thiserror::Error;

use crate::Geometry;

/// A configuration that cannot lay out the span arrays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// A size that must be positive is zero.
    #[error("{field} must be positive")]
    Zero {
        /// The size that is zero.
        field: &'static str,
    },

    /// The history does not split into whole chunks of epochs.
    #[error("history of {history} epochs is not a multiple of the chunk of {chunk} epochs")]
    Indivisible {
        /// Epochs of history.
        history: u64,
        /// Epochs per chunk.
        chunk: u64,
    },

    /// The history is longer than a 16-bit distance can span.
    #[error("history of {history} epochs exceeds the limit of {limit}")]
    HistoryTooLong {
        /// Epochs of history asked for.
        history: u64,
        /// The longest history a cell can encode.
        limit: u64,
    },
}

/// Why the slasher failed.
#[derive(Debug, Error)]
pub enum SlasherError {
    /// The configuration is invalid.
    #[error("invalid slasher configuration: {0}")]
    Config(#[from] ConfigError),

    /// The database was written under another layout, which its chunks cannot be read with.
    #[error("database laid out as {stored:?}, configured as {configured:?}")]
    GeometryMismatch {
        /// The layout on disk.
        stored: Geometry,
        /// The layout asked for.
        configured: Geometry,
    },

    /// The key-value store failed.
    #[error("slasher store: {0}")]
    Store(#[from] axiom_store::Error),

    /// A stored record does not decode.
    #[error("corrupt {table} record of {len} bytes: {reason}")]
    Corrupt {
        /// The table holding it.
        table: &'static str,
        /// Its length in bytes.
        len: usize,
        /// What is wrong with it.
        reason: &'static str,
    },

    /// A stored chunk does not decompress.
    #[error("corrupt {table} chunk: {source}")]
    Compression {
        /// The table holding it.
        table: &'static str,
        /// The decompressor's error.
        #[source]
        source: SnappyError,
    },

    /// A stored container does not decode.
    #[error("corrupt {table} container: {source}")]
    Decode {
        /// The table holding it.
        table: &'static str,
        /// The decoder's error.
        #[source]
        source: DecodeError,
    },

    /// A record names a vote the database no longer holds.
    #[error("no stored vote {id} with target epoch {target}")]
    MissingVote {
        /// Target epoch of the vote.
        target: Epoch,
        /// Its number within the epoch.
        id: u32,
    },

    /// One epoch received more distinct votes than a record can number.
    #[error("target epoch {0} ran out of vote numbers")]
    VoteNumbersExhausted(Epoch),
}

/// Why evidence does not fit a fork's slashing container.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum EvidenceError {
    /// A vote has more signers than the fork's indexed attestation may list.
    #[error("{count} signers exceed the {limit} a {fork} indexed attestation holds")]
    TooManySigners {
        /// The fork whose container was asked for.
        fork: ForkName,
        /// Signers of the vote.
        count: usize,
        /// The container's limit.
        limit: usize,
    },
}
