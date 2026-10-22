//! Entry metadata recovered from a segment, without the value.

use crate::{
    format::{EntryHeader, Kind},
    slot::Location,
};

/// Everything the index needs about one entry: all of it except the value bytes.
///
/// Recovery and compaction work on these, so neither ever holds a value in memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    /// What the entry does to its key.
    pub(crate) kind: Kind,
    /// Identifier of the table the key belongs to.
    pub(crate) table: u8,
    /// The key.
    pub(crate) key: Box<[u8]>,
    /// Bytes of value, zero for a tombstone.
    pub(crate) value_len: u32,
    /// Offset of the entry header from the start of its segment file.
    pub(crate) offset: u64,
}

impl Record {
    /// Returns the bytes the entry occupies on disk.
    pub(crate) const fn entry_len(&self) -> u64 {
        EntryHeader::len_for(self.key.len(), self.value_len)
    }

    /// Returns where a put entry's value lives, given the segment holding it.
    pub(crate) const fn location(&self, segment: u32) -> Location {
        Location {
            segment,
            value_len: self.value_len,
            offset: self.offset,
        }
    }
}
