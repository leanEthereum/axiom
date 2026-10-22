//! Reasons a storage operation fails.

use std::{io, path::PathBuf};

use thiserror::Error;

use crate::Table;

/// A storage operation that could not complete.
///
/// Every variant leaves the store consistent, except where it says otherwise.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The operating system reported an input or output failure.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// Another handle, in this process or another, holds the database directory.
    #[error("database {} is locked by another handle", .0.display())]
    Locked(PathBuf),

    /// Bytes on disk do not match the checksum or layout they claim.
    #[error("corrupt record in segment {segment} at offset {offset}: {reason}")]
    Corruption {
        /// Segment holding the bad bytes.
        segment: u32,
        /// Byte offset of the bad record inside the segment.
        offset: u64,
        /// Rule the bytes broke.
        reason: &'static str,
    },

    /// A key is longer than the 16-bit length field of a record allows.
    #[error("key of {0} bytes exceeds 65535 bytes")]
    KeyTooLong(usize),

    /// A value is longer than the 32-bit length field of a record allows.
    #[error("value of {0} bytes exceeds 4294967295 bytes")]
    ValueTooLong(usize),

    /// A batch holds more operations than its 32-bit count field allows.
    #[error("batch exceeds 4294967295 operations")]
    BatchTooLarge,

    /// A table name is empty or longer than the limit.
    #[error("table name must be 1 to 64 bytes")]
    InvalidTableName,

    /// Every one of the 255 table identifiers is taken.
    #[error("all 255 table identifiers are taken")]
    TooManyTables,

    /// A table handle belongs to another store.
    #[error("{0:?} does not belong to this store")]
    UnknownTable(Table),

    /// The options break a documented bound.
    #[error("invalid options: {0}")]
    InvalidOptions(&'static str),

    /// An earlier write or sync failed, so the tail of the log is in an unknown state.
    ///
    /// The store refuses further writes.
    /// Reopening it runs recovery, which restores the last durable batch.
    #[error("an earlier write failed; reopen the store to recover")]
    Poisoned,
}
