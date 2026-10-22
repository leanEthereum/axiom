//! Ordered iteration over a table of a snapshot.

use std::{fmt, ops::Bound, sync::Arc};

use crate::{Error, Table, map::Cursor, metrics::Counters, slot::Slot, version::Version};

/// An ordered iterator over the entries of a table, as of one snapshot.
///
/// Keys come in ascending byte order from the front and descending order from the back.
/// Each value is read and verified when its entry is reached, never ahead of time.
///
/// The iterator owns its snapshot, so it outlives the store handle that created it.
pub struct Iter {
    /// Position in the index.
    cursor: Cursor<Slot>,
    /// The snapshot being iterated, which keeps its segments open.
    version: Arc<Version>,
    /// Counters charged for value reads.
    counters: Arc<Counters>,
    /// Table being iterated.
    table: Table,
}

impl Iter {
    /// Positions an iterator on the keys of a table within two bounds.
    pub(crate) fn new(
        version: Arc<Version>,
        counters: Arc<Counters>,
        table: Table,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
    ) -> Result<Self, Error> {
        let cursor = version.table(table)?.range(lower, upper);
        Ok(Self {
            cursor,
            version,
            counters,
            table,
        })
    }

    /// Drops the values and iterates the keys alone, without any disk access.
    #[must_use]
    pub fn keys(self) -> Keys {
        Keys {
            cursor: self.cursor,
        }
    }

    /// Reads the value of one index node into an owned entry.
    fn entry(&self, key: &[u8], slot: &Slot) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let value = self
            .version
            .read(self.table.id(), key, slot, &self.counters)?;
        Ok((key.to_vec(), value))
    }
}

impl Iterator for Iter {
    type Item = Result<(Vec<u8>, Vec<u8>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.cursor.next()?;
        Some(self.entry(node.key(), node.value()))
    }
}

impl DoubleEndedIterator for Iter {
    fn next_back(&mut self) -> Option<Self::Item> {
        let node = self.cursor.next_back()?;
        Some(self.entry(node.key(), node.value()))
    }
}

impl fmt::Debug for Iter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Iter")
            .field("table", &self.table)
            .finish_non_exhaustive()
    }
}

/// An ordered iterator over the keys of a table, as of one snapshot.
///
/// Keys live in memory, so this never touches the disk and never fails.
pub struct Keys {
    /// Position in the index.
    cursor: Cursor<Slot>,
}

impl Iterator for Keys {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        self.cursor.next().map(|node| node.key().to_vec())
    }
}

impl DoubleEndedIterator for Keys {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.cursor.next_back().map(|node| node.key().to_vec())
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys").finish_non_exhaustive()
    }
}
