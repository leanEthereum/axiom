//! Reasons a storage operation fails.

use std::{error, fmt, io, path::PathBuf};

use crate::Table;

/// A storage operation that could not complete.
///
/// Every variant leaves the store consistent, except where it says otherwise.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The operating system reported an input or output failure.
    Io(io::Error),

    /// Another handle, in this process or another, holds the database directory.
    Locked(PathBuf),

    /// Bytes on disk do not match the checksum or layout they claim.
    Corruption {
        /// Segment holding the bad bytes.
        segment: u32,
        /// Byte offset of the bad record inside the segment.
        offset: u64,
        /// Rule the bytes broke.
        reason: &'static str,
    },

    /// A key is longer than the 16-bit length field of a record allows.
    KeyTooLong(usize),

    /// A value is longer than the 32-bit length field of a record allows.
    ValueTooLong(usize),

    /// A batch holds more operations than its 32-bit count field allows.
    BatchTooLarge,

    /// A table name is empty or longer than the limit.
    InvalidTableName,

    /// Every one of the 255 table identifiers is taken.
    TooManyTables,

    /// A table handle belongs to another store.
    UnknownTable(Table),

    /// The options break a documented bound.
    InvalidOptions(&'static str),

    /// An earlier write or sync failed, so the tail of the log is in an unknown state.
    ///
    /// The store refuses further writes.
    /// Reopening it runs recovery, which restores the last durable batch.
    Poisoned,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "i/o error: {err}"),
            Self::Locked(path) => {
                write!(f, "database {} is locked by another handle", path.display())
            }
            Self::Corruption {
                segment,
                offset,
                reason,
            } => write!(
                f,
                "corrupt record in segment {segment} at offset {offset}: {reason}"
            ),
            Self::KeyTooLong(len) => write!(f, "key of {len} bytes exceeds 65535 bytes"),
            Self::ValueTooLong(len) => write!(f, "value of {len} bytes exceeds 4294967295 bytes"),
            Self::BatchTooLarge => f.write_str("batch exceeds 4294967295 operations"),
            Self::InvalidTableName => f.write_str("table name must be 1 to 64 bytes"),
            Self::TooManyTables => f.write_str("all 255 table identifiers are taken"),
            Self::UnknownTable(table) => write!(f, "{table:?} does not belong to this store"),
            Self::InvalidOptions(reason) => write!(f, "invalid options: {reason}"),
            Self::Poisoned => f.write_str("an earlier write failed; reopen the store to recover"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
