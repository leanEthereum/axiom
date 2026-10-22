//! The store handle: one type for the disk and memory backends.

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use crate::{
    Batch, Error, Metrics, Options, Snapshot, Table,
    format::Kind,
    log::{Log, Shared},
    metrics::Counters,
    slot::Slot,
    version::Version,
};

/// Longest accepted table name, in bytes.
///
/// Names are identifiers chosen by code, not data; a small bound keeps the catalog tiny.
const MAX_TABLE_NAME: usize = 64;

/// An embedded, crash-safe key-value store with named tables.
///
/// The handle is shareable across threads.
/// Reads never wait for writes; writes are serialized.
///
/// # Examples
///
/// ```
/// use axiom_store::{Options, Store};
///
/// let dir = std::env::temp_dir().join(format!("axiom-store-doc-{}", std::process::id()));
/// # std::fs::remove_dir_all(&dir).ok();
/// {
///     let store = Store::open(&dir, Options::default()).unwrap();
///     let blocks = store.table("blocks").unwrap();
///     store.put(blocks, b"root", b"block").unwrap();
/// }
///
/// // Reopening replays the log: the write is still there.
/// let store = Store::open(&dir, Options::default()).unwrap();
/// let blocks = store.table("blocks").unwrap();
/// assert_eq!(store.get(blocks, b"root").unwrap(), Some(b"block".to_vec()));
/// # drop(store);
/// # std::fs::remove_dir_all(&dir).unwrap();
/// ```
#[derive(Debug)]
pub struct Store {
    /// The latest committed state, cloned by readers and swapped by the writer.
    current: Shared,
    /// The writer lock, guarding the log; empty for the memory backend.
    log: Mutex<Option<Log>>,
    /// Operation counters, shared with snapshots.
    counters: Arc<Counters>,
}

impl Store {
    /// Opens the store in a directory, creating it if needed, and recovers its contents.
    ///
    /// Recovery restores exactly the batches committed before the last close or crash.
    /// A torn batch at the end of the log is discarded whole.
    ///
    /// # Errors
    ///
    /// - Another handle holds the directory.
    /// - The options break a documented bound.
    /// - A sealed segment is corrupt.
    /// - The filesystem reports an error.
    pub fn open(path: impl AsRef<Path>, options: Options) -> Result<Self, Error> {
        let (log, version) = Log::open(path.as_ref(), options)?;
        Ok(Self {
            current: Shared::new(Arc::new(version)),
            log: Mutex::new(Some(log)),
            counters: Arc::default(),
        })
    }

    /// Creates an empty store that lives in memory only.
    ///
    /// It behaves exactly like a store on disk, minus durability.
    /// Use it in tests and simulations.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            current: Shared::new(Arc::new(Version::new())),
            log: Mutex::new(None),
            counters: Arc::default(),
        }
    }

    /// Returns the handle of a table, creating the table on first use.
    ///
    /// The name-to-handle mapping is persisted, so a name gets the same handle after reopening.
    ///
    /// # Errors
    ///
    /// - The name is empty or longer than 64 bytes.
    /// - All 255 tables exist.
    /// - Recording the new table fails.
    pub fn table(&self, name: &str) -> Result<Table, Error> {
        if name.is_empty() || name.len() > MAX_TABLE_NAME {
            return Err(Error::InvalidTableName);
        }
        // Hold the writer lock across lookup and creation, so two threads agree on one handle.
        let mut log = self.lock_log();
        let version = self.version();
        if let Some(table) = version.find_table(name) {
            return Ok(table);
        }

        // Identifiers are dense: the next one is the current count, catalog included.
        //
        //     tables [catalog, blocks, states] -> count 3 -> new table gets identifier 3
        let id = u8::try_from(version.table_count()).map_err(|_| Error::TooManyTables)?;
        let mut key = Vec::with_capacity(1 + name.len());
        key.push(id);
        key.extend_from_slice(name.as_bytes());
        let mut batch = Batch::new();
        batch.put(Table::CATALOG, &key, &[])?;
        self.commit(&mut log, &batch)?;
        Ok(Table::from_id(id))
    }

    /// Returns the value bound to a key.
    ///
    /// # Errors
    ///
    /// Fails on an unknown table, a read error, or a value whose checksum does not hold.
    pub fn get(&self, table: Table, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.snapshot().get(table, key)
    }

    /// Returns whether a key is present, from memory alone.
    ///
    /// # Errors
    ///
    /// Fails on an unknown table.
    pub fn contains_key(&self, table: Table, key: &[u8]) -> Result<bool, Error> {
        self.snapshot().contains_key(table, key)
    }

    /// Binds a key to a value, as a batch of one.
    ///
    /// # Errors
    ///
    /// Fails like a batch write.
    pub fn put(&self, table: Table, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let mut batch = Batch::new();
        batch.put(table, key, value)?;
        self.write(&batch)
    }

    /// Removes a key, as a batch of one.
    ///
    /// # Errors
    ///
    /// Fails like a batch write.
    pub fn delete(&self, table: Table, key: &[u8]) -> Result<(), Error> {
        let mut batch = Batch::new();
        batch.delete(table, key)?;
        self.write(&batch)
    }

    /// Commits a batch atomically.
    ///
    /// After a crash, recovery restores either every operation of the batch or none.
    /// Concurrent readers likewise see all of it or none of it.
    ///
    /// # Errors
    ///
    /// Fails on a table of another store, an earlier unrecovered failure, or an I/O error.
    /// An I/O error poisons the store: reopen it to recover.
    pub fn write(&self, batch: &Batch) -> Result<(), Error> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut log = self.lock_log();
        // User handles never name the catalog, so every identifier must already exist.
        batch.tables_within(self.version().table_count())?;
        self.commit(&mut log, batch)
    }

    /// Takes a consistent view of every table.
    ///
    /// The snapshot costs O(1) to take, holds no lock, and sees no later write.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot::new(self.version(), Arc::clone(&self.counters))
    }

    /// Rewrites mostly-dead segments to reclaim disk space.
    ///
    /// Readers keep running; writers wait until the pass ends.
    /// Does nothing for the memory backend.
    ///
    /// # Errors
    ///
    /// Fails on an I/O error, which poisons the store, or on a corrupt segment.
    pub fn compact(&self) -> Result<(), Error> {
        match self.lock_log().as_mut() {
            Some(log) => log.compact(&self.current, &self.counters),
            None => Ok(()),
        }
    }

    /// Flushes every committed batch to stable storage.
    ///
    /// Only needed under the manual sync policy.
    ///
    /// # Errors
    ///
    /// Fails on an I/O error, which poisons the store.
    pub fn sync(&self) -> Result<(), Error> {
        match self.lock_log().as_mut() {
            Some(log) => log.sync(&self.counters),
            None => Ok(()),
        }
    }

    /// Reads the operation counters and the current disk usage.
    #[must_use]
    pub fn metrics(&self) -> Metrics {
        let (segments, disk_bytes, live_bytes) =
            self.lock_log().as_ref().map_or((0, 0, 0), Log::totals);
        self.counters.snapshot(segments, disk_bytes, live_bytes)
    }

    /// Appends a validated batch through the backend.
    fn commit(&self, log: &mut MutexGuard<'_, Option<Log>>, batch: &Batch) -> Result<(), Error> {
        if let Some(log) = log.as_mut() {
            return log.commit(batch, &self.current, &self.counters);
        }

        // Memory backend: the batch becomes shared values in a new version.
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        let version = Arc::make_mut(&mut current);
        for entry in batch.entries() {
            let slot = (entry.kind == Kind::Put).then(|| Slot::Memory(entry.value.into()));
            version.apply(entry.table.id(), entry.key, slot);
        }
        drop(current);
        self.counters.record_batch(batch.frame().len() as u64);
        Ok(())
    }

    /// Returns the latest committed state.
    fn version(&self) -> Arc<Version> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Takes the writer lock.
    ///
    /// A panic while holding it cannot leave the log half-written in memory:
    /// every state change follows a completed I/O step, so the guard is safe to reuse.
    fn lock_log(&self) -> MutexGuard<'_, Option<Log>> {
        self.log.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
