//! Consistent, lock-free reads of one state of the store.

use std::{
    ops::{Bound, RangeBounds},
    sync::Arc,
};

use crate::{Error, Iter, Table, metrics::Counters, version::Version};

/// A frozen view of every table at one instant.
///
/// Writes committed after the snapshot was taken are invisible to it.
/// A batch is either wholly visible or wholly invisible.
///
/// Taking a snapshot costs O(1) and holds no lock.
/// The store keeps writing meanwhile.
/// A later write copies only the O(log n) index nodes on its path.
///
/// A snapshot keeps the segment files it needs open, even across compaction.
/// Holding one for hours therefore pins the disk space of rewritten segments.
///
/// # Examples
///
/// ```
/// use axiom_store::Store;
///
/// let store = Store::in_memory();
/// let states = store.table("states").unwrap();
/// store.put(states, b"slot 1", b"old").unwrap();
///
/// let snapshot = store.snapshot();
/// store.put(states, b"slot 1", b"new").unwrap();
///
/// assert_eq!(
///     snapshot.get(states, b"slot 1").unwrap(),
///     Some(b"old".to_vec())
/// );
/// assert_eq!(store.get(states, b"slot 1").unwrap(), Some(b"new".to_vec()));
/// ```
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// The frozen state.
    version: Arc<Version>,
    /// Counters charged for value reads.
    counters: Arc<Counters>,
}

impl Snapshot {
    /// Wraps a state for reading.
    pub(crate) const fn new(version: Arc<Version>, counters: Arc<Counters>) -> Self {
        Self { version, counters }
    }

    /// Returns the value bound to a key.
    ///
    /// # Errors
    ///
    /// Fails on an unknown table, a read error, or a value whose checksum does not hold.
    pub fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let Some(slot) = self.version.table(table)?.get(key) else {
            return Ok(None);
        };
        self.version
            .read(table.id(), key, slot, &self.counters)
            .map(Some)
    }

    /// Returns whether a key is present, from memory alone.
    ///
    /// # Errors
    ///
    /// Fails on an unknown table.
    pub fn contains_key(&self, table: Table, key: &[u8]) -> Result<bool, Error> {
        Ok(self.version.table(table)?.get(key).is_some())
    }

    /// Returns the number of keys in a table.
    ///
    /// # Errors
    ///
    /// Fails on an unknown table.
    pub fn len(&self, table: Table) -> Result<usize, Error> {
        Ok(self.version.table(table)?.len())
    }

    /// Iterates every entry of a table in key order.
    ///
    /// # Errors
    ///
    /// Fails on an unknown table.
    pub fn entries(&self, table: Table) -> Result<Iter, Error> {
        self.bounded(table, Bound::Unbounded, Bound::Unbounded)
    }

    /// Iterates the entries of a table whose keys fall in a range.
    ///
    /// An empty or inverted range yields nothing.
    ///
    /// # Errors
    ///
    /// Fails on an unknown table.
    ///
    /// # Examples
    ///
    /// ```
    /// use axiom_store::Store;
    ///
    /// let store = Store::in_memory();
    /// let blocks = store.table("blocks_by_slot").unwrap();
    /// for slot in 0u64..10 {
    ///     store.put(blocks, &slot.to_be_bytes(), b"block").unwrap();
    /// }
    ///
    /// let lower = 3u64.to_be_bytes();
    /// let upper = 6u64.to_be_bytes();
    /// let keys: Vec<_> = store
    ///     .snapshot()
    ///     .range(blocks, &lower[..]..&upper[..])
    ///     .unwrap()
    ///     .keys()
    ///     .collect();
    /// assert_eq!(keys.len(), 3);
    /// ```
    pub fn range<K, R>(&self, table: Table, range: R) -> Result<Iter, Error>
    where
        K: AsRef<[u8]> + ?Sized,
        R: RangeBounds<K>,
    {
        let lower = range.start_bound().map(AsRef::as_ref);
        let upper = range.end_bound().map(AsRef::as_ref);
        self.bounded(table, lower, upper)
    }

    /// Iterates the entries of a table whose keys start with a prefix.
    ///
    /// # Errors
    ///
    /// Fails on an unknown table.
    pub fn prefix(&self, table: Table, prefix: &[u8]) -> Result<Iter, Error> {
        // The keys with a prefix form the range from the prefix up to its successor.
        //
        //     prefix [0x01, 0xff]  ->  successor [0x02]  ->  range [0x01 0xff] .. [0x02]
        //     prefix [0xff, 0xff]  ->  no successor      ->  range [0xff 0xff] .. end
        let mut successor = prefix.to_vec();
        while let Some(last) = successor.pop() {
            if last < u8::MAX {
                successor.push(last + 1);
                return self.bounded(table, Bound::Included(prefix), Bound::Excluded(&successor));
            }
        }
        self.bounded(table, Bound::Included(prefix), Bound::Unbounded)
    }

    /// Iterates the entries of a table within two bounds.
    fn bounded(
        &self,
        table: Table,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
    ) -> Result<Iter, Error> {
        Iter::new(
            Arc::clone(&self.version),
            Arc::clone(&self.counters),
            table,
            lower,
            upper,
        )
    }
}
