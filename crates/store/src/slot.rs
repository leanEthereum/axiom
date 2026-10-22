//! Where the index finds a value.

use std::sync::Arc;

use crate::format::entry_len;

/// The position of one put entry inside a segment file.
///
/// The index stores this instead of the value, so a 300 MB state costs 16 bytes of memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Location {
    /// Segment holding the entry.
    pub(crate) segment: u32,
    /// Bytes of value, to size the read buffer before touching the disk.
    pub(crate) value_len: u32,
    /// Offset of the entry header from the start of the segment file.
    pub(crate) offset: u64,
}

impl Location {
    /// Returns the bytes the entry occupies on disk, given its key length.
    pub(crate) const fn entry_len(self, key_len: usize) -> u64 {
        entry_len(key_len, self.value_len)
    }
}

/// The value side of an index entry.
///
/// The disk backend stores locations and the memory backend stores the bytes themselves.
/// Sharing one index type lets both backends share every other line of code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Slot {
    /// The value lives in a segment file.
    Disk(Location),
    /// The value lives in memory, shared by every snapshot that sees it.
    Memory(Arc<[u8]>),
}
