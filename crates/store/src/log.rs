//! The write-ahead log: recovery, appends, rotation, and compaction.
//!
//! # Overview
//!
//! The log is the database.
//! There is no separate data file to update in place: a committed frame is the data.
//!
//! ```text
//!     sealed                          sealed             active
//!     +----------------+------+       +-------+------+   +------------------+
//!     | 00000000.seg   | hint |  ...  | 0007  | hint |   | 00000008.seg     | <- appends
//!     +----------------+------+       +-------+------+   +------------------+
//!       immutable, indexed by hint                         scanned at open
//! ```
//!
//! # Invariants
//!
//! - Only the active segment is ever appended to, and only by the holder of the writer lock.
//! - A frame never spans two segments, so a batch lives or dies in one file.
//! - Every sealed segment was fully synced before the next one was created.
//!   Only the active segment can therefore end in a torn frame.
//! - Higher segment identifiers hold newer entries, so replay in identifier order is log order.

use std::{
    fs, io,
    path::Path,
    sync::{Arc, PoisonError, RwLock},
};

use crate::{
    Batch, Error, Options, SyncPolicy,
    compaction::Plan,
    directory::Directory,
    format::{FILE_HEADER_LEN, FRAME_HEADER_LEN, FrameHeader, Kind},
    hint::Hint,
    metrics::Counters,
    record::Record,
    scan::Scan,
    segment::Segment,
    slot::{Location, Slot},
    usage::Ledger,
    version::Version,
};

/// Entries per frame written by compaction.
///
/// Bounds the frame count field and lets a rotation fall between frames of one pass.
const COMPACTION_FRAME_ENTRIES: usize = 4096;

/// The current state of the store, swapped atomically on every commit.
pub(crate) type Shared = RwLock<Arc<Version>>;

/// The writer side of an on-disk store.
#[derive(Debug)]
pub(crate) struct Log {
    /// The locked database directory.
    directory: Directory,
    /// Configuration fixed at open.
    options: Options,
    /// The segment receiving appends.
    active: Arc<Segment>,
    /// Bytes of the active segment that hold whole frames.
    active_len: u64,
    /// Metadata of every entry in the active segment, its future hint.
    active_records: Vec<Record>,
    /// Live and dead bytes of every segment.
    ledger: Ledger,
    /// Whether an I/O failure left the tail of the log in an unknown state.
    poisoned: bool,
}

impl Log {
    /// Opens or creates a store directory and rebuilds the index from it.
    ///
    /// # Algorithm
    ///
    /// ```text
    ///     Phase 1  lock the directory, delete temporary files and orphan hints
    ///     Phase 2  sealed segments: load each hint, or scan and rewrite it
    ///     Phase 3  active segment: scan, truncate at the first bad frame
    ///     replay every record in segment order into the index
    /// ```
    pub(crate) fn open(path: &Path, options: Options) -> Result<(Self, Version), Error> {
        // Phase 1: exclusive ownership and a clean listing.
        options.validate()?;
        let directory = Directory::open(path)?;
        let ids = directory.clean_and_list()?;
        let mut version = Version::new();
        let mut ledger = Ledger::default();

        // Phase 2: sealed segments are complete by construction.
        let (active_id, sealed) = ids
            .split_last()
            .map_or((0, &[][..]), |(&last, sealed)| (last, sealed));
        for &id in sealed {
            let segment = Segment::open(&directory, id)?;
            if !segment.has_valid_header()? {
                return Err(Error::Corruption {
                    segment: id,
                    offset: 0,
                    reason: "bad segment header",
                });
            }
            let records = match Hint::read(&directory, id)? {
                Some(records) => records,
                None => {
                    // No usable hint: verify the whole segment, then write the hint for next time.
                    let scan = Scan::run(&segment)?;
                    if let Some(reason) = scan.damage {
                        // A sealed segment was synced whole, so damage here is media corruption.
                        return Err(Error::Corruption {
                            segment: id,
                            offset: scan.valid_len,
                            reason,
                        });
                    }
                    Hint::write(&directory, id, &scan.records)?;
                    scan.records
                }
            };
            ledger.open(id, segment.len()? - FILE_HEADER_LEN);
            version.add_segment(Arc::new(segment));
            Self::replay(&mut version, &mut ledger, id, &records);
        }

        // Phase 3: the active segment may end in a torn frame.
        let active = if ids.is_empty() {
            Segment::create(&directory, active_id)?
        } else {
            let segment = Segment::open(&directory, active_id)?;
            // A hint describes a sealed segment; this one will grow again.
            Hint::remove(&directory, active_id)?;
            if segment.len()? < FILE_HEADER_LEN {
                // The crash hit while the header was being written: nothing else exists yet.
                segment.truncate(0)?;
                segment.write_header()?;
            } else if !segment.has_valid_header()? {
                return Err(Error::Corruption {
                    segment: active_id,
                    offset: 0,
                    reason: "bad segment header",
                });
            }
            segment
        };
        let scan = Scan::run(&active)?;
        if scan.damage.is_some() {
            // Cut the torn tail so the next append starts on a frame boundary.
            //
            //     | header | frame ok | frame ok | torn ... |
            //                                    ^ truncate here
            active.truncate(scan.valid_len)?;
        }
        let active = Arc::new(active);
        ledger.open(active_id, scan.valid_len - FILE_HEADER_LEN);
        version.add_segment(Arc::clone(&active));
        Self::replay(&mut version, &mut ledger, active_id, &scan.records);

        let log = Self {
            directory,
            options,
            active,
            active_len: scan.valid_len,
            active_records: scan.records,
            ledger,
            poisoned: false,
        };
        Ok((log, version))
    }

    /// Applies recovered records of one segment to the index, in log order.
    fn replay(version: &mut Version, ledger: &mut Ledger, segment: u32, records: &[Record]) {
        for record in records {
            let slot = match record.kind {
                Kind::Put => Some(Slot::Disk(record.location(segment))),
                Kind::Delete => None,
            };
            let displaced = version.apply(record.table, &record.key, slot.clone());
            ledger.exchange(record.key.len(), displaced.as_ref(), slot.as_ref());
        }
    }

    /// Appends a batch, makes it durable per the sync policy, then publishes it.
    ///
    /// # Algorithm
    ///
    /// ```text
    ///     1. rotate if the frame would overflow a non-empty active segment
    ///     2. one positional write of the whole frame at the end of the log
    ///     3. sync, under the every-batch policy
    ///     4. swap in a new version: readers see all of the batch or none of it
    /// ```
    pub(crate) fn commit(
        &mut self,
        batch: &Batch,
        shared: &Shared,
        counters: &Counters,
    ) -> Result<(), Error> {
        self.ensure_healthy()?;
        let frame = batch.frame();
        let frame_len = frame.len() as u64;

        // Step 1: a frame never straddles two segments.
        let rotated = self.needs_rotation(frame_len);
        if rotated {
            self.rotate(shared, counters)?;
        }

        // Step 2: append. A failure poisons the log: its tail is now unknown.
        let offset = self.active_len;
        let written = self.active.write_at(frame, offset);
        self.check(written)?;

        // Step 3: durability before visibility.
        if self.options.sync == SyncPolicy::EveryBatch {
            let synced = self.active.sync();
            self.check(synced)?;
            counters.record_sync();
        }
        self.active_len += frame_len;
        self.ledger.grow(self.active.id(), frame_len);
        counters.record_batch(frame_len);

        // Step 4: publish under the version lock, held only for the in-memory updates.
        {
            let mut current = shared.write().unwrap_or_else(PoisonError::into_inner);
            let version = Arc::make_mut(&mut current);
            for entry in batch.entries() {
                // Invariant: batch construction bounds values to 32-bit lengths.
                let location = Location {
                    segment: self.active.id(),
                    value_len: entry.value.len() as u32,
                    offset: offset + entry.position,
                };
                let slot = (entry.kind == Kind::Put).then_some(Slot::Disk(location));
                let displaced = version.apply(entry.table.id(), entry.key, slot.clone());
                self.ledger
                    .exchange(entry.key.len(), displaced.as_ref(), slot.as_ref());
                self.active_records.push(Record {
                    kind: entry.kind,
                    table: entry.table.id(),
                    key: entry.key.into(),
                    value_len: location.value_len,
                    offset: location.offset,
                });
            }
            drop(current);
        }

        if rotated && self.options.auto_compact {
            self.compact(shared, counters)?;
        }
        Ok(())
    }

    /// Flushes the active segment to stable storage.
    pub(crate) fn sync(&mut self, counters: &Counters) -> Result<(), Error> {
        self.ensure_healthy()?;
        let synced = self.active.sync();
        self.check(synced)?;
        counters.record_sync();
        Ok(())
    }

    /// Returns the number of segments, their frame bytes, and their live bytes.
    pub(crate) fn totals(&self) -> (u64, u64, u64) {
        self.ledger.totals()
    }

    /// Rewrites every sealed segment whose dead share reaches the threshold.
    ///
    /// # Algorithm
    ///
    /// ```text
    ///     Phase 1  seal the active segment if it is itself mostly dead
    ///     Phase 2  copy each victim's surviving entries to the end of the log
    ///     Phase 3  sync the copies
    ///     Phase 4  publish a version pointing at the copies, without the victims
    ///     Phase 5  delete the victims, oldest first
    /// ```
    ///
    /// Readers are never blocked; writers wait for the pass to finish.
    pub(crate) fn compact(&mut self, shared: &Shared, counters: &Counters) -> Result<(), Error> {
        self.ensure_healthy()?;
        let threshold = self.options.compaction_threshold;

        // Phase 1: the active segment cannot be rewritten into itself, so seal it first.
        let active_usage = self.ledger.usage(self.active.id());
        if active_usage.total > 0 && active_usage.is_garbage(threshold) {
            self.rotate(shared, counters)?;
        }
        let plan = Plan::select(&self.ledger, self.active.id(), threshold);
        if plan.victims().is_empty() {
            return Ok(());
        }

        // Phase 2: the writer lock is held, so this version stays current until Phase 4.
        let version = Arc::clone(&shared.read().unwrap_or_else(PoisonError::into_inner));
        let mut moved = Vec::new();
        let mut copied = 0;
        for &victim in plan.victims() {
            let source = version.segment(victim).cloned().ok_or(Error::Corruption {
                segment: victim,
                offset: 0,
                reason: "compaction victim is not open",
            })?;
            let records = self.victim_records(&source)?;
            let survivors: Vec<&Record> = records
                .iter()
                .filter(|record| plan.retains(victim, record, &version))
                .collect();
            for chunk in survivors.chunks(COMPACTION_FRAME_ENTRIES) {
                copied += self.copy_frame(&source, chunk, &mut moved, shared, counters)?;
            }
        }

        // Phase 3: the copies must be durable before any original disappears.
        let synced = self.active.sync();
        self.check(synced)?;
        counters.record_sync();

        // Phase 4: repoint the index at the copies and retire the victims.
        {
            let mut current = shared.write().unwrap_or_else(PoisonError::into_inner);
            let version = Arc::make_mut(&mut current);
            for (table, key, location) in moved {
                let slot = Slot::Disk(location);
                let displaced = version.apply(table, &key, Some(slot.clone()));
                self.ledger
                    .exchange(key.len(), displaced.as_ref(), Some(&slot));
            }
            for &victim in plan.victims() {
                version.remove_segment(victim);
            }
            drop(current);
        }

        // Phase 5: oldest first, so a crash never keeps a put while losing its tombstone.
        let mut freed = 0;
        for &victim in plan.victims() {
            freed += self.ledger.close(victim).total + FILE_HEADER_LEN;
            let removed = Hint::remove(&self.directory, victim)
                .and_then(|()| fs::remove_file(self.directory.segment_path(victim)));
            self.check(removed)?;
        }
        let synced = self.directory.sync();
        self.check(synced)?;
        counters.record_compaction(freed.saturating_sub(copied));
        Ok(())
    }

    /// Returns the entry metadata of a sealed segment, from its hint or a full scan.
    fn victim_records(&self, segment: &Segment) -> Result<Vec<Record>, Error> {
        if let Some(records) = Hint::read(&self.directory, segment.id())? {
            return Ok(records);
        }
        let scan = Scan::run(segment)?;
        match scan.damage {
            None => Ok(scan.records),
            Some(reason) => Err(Error::Corruption {
                segment: segment.id(),
                offset: scan.valid_len,
                reason,
            }),
        }
    }

    /// Copies entries of a victim into one new frame, returning the bytes written.
    ///
    /// Moved puts are collected for the index update; tombstones need none.
    fn copy_frame(
        &mut self,
        source: &Segment,
        entries: &[&Record],
        moved: &mut Vec<(u8, Box<[u8]>, Location)>,
        shared: &Shared,
        counters: &Counters,
    ) -> Result<u64, Error> {
        let body: u64 = entries.iter().map(|record| record.entry_len()).sum();
        let frame_len = FRAME_HEADER_LEN as u64 + body;
        if self.needs_rotation(frame_len) {
            self.rotate(shared, counters)?;
        }

        // The header first: the entries keep their own checksums, copied verbatim.
        //
        // Invariant: chunks hold at most 4096 entries, far below the 32-bit count limit.
        let header = FrameHeader {
            len: body,
            count: entries.len() as u32,
        };
        let start = self.active_len;
        let written = self.active.write_at(&header.encode(), start);
        self.check(written)?;

        // Coalesce runs of adjacent entries into one kernel copy each.
        //
        //     victim:  | e1 | e2 | dead | e3 |    -> two copies: [e1 e2], [e3]
        let mut position = start + FRAME_HEADER_LEN as u64;
        let mut run: Option<(u64, u64, u64)> = None;
        for record in entries {
            let len = record.entry_len();
            run = match run {
                // The entry continues the current run in both files.
                Some((from, to, run_len)) if from + run_len == record.offset => {
                    Some((from, to, run_len + len))
                }
                // A gap in the victim: flush the run, start a new one.
                Some((from, to, run_len)) => {
                    let copy = self.active.copy_from(source, from, to, run_len);
                    self.check(copy)?;
                    Some((record.offset, position, len))
                }
                None => Some((record.offset, position, len)),
            };

            // The entry's new home, for the hint and the index.
            self.active_records.push(Record {
                offset: position,
                ..(*record).clone()
            });
            if record.kind == Kind::Put {
                moved.push((
                    record.table,
                    record.key.clone(),
                    Location {
                        segment: self.active.id(),
                        value_len: record.value_len,
                        offset: position,
                    },
                ));
            }
            position += len;
        }
        if let Some((from, to, run_len)) = run {
            let copy = self.active.copy_from(source, from, to, run_len);
            self.check(copy)?;
        }

        self.active_len = position;
        self.ledger.grow(self.active.id(), frame_len);
        counters.record_write(frame_len);
        Ok(frame_len)
    }

    /// Returns whether a frame must go to a fresh segment.
    ///
    /// An empty segment accepts any frame, so an oversized batch still commits.
    const fn needs_rotation(&self, frame_len: u64) -> bool {
        self.active_len > FILE_HEADER_LEN && self.active_len + frame_len > self.options.segment_size
    }

    /// Seals the active segment and starts the next one.
    ///
    /// # Algorithm
    ///
    /// ```text
    ///     sync segment n  ->  write hint n  ->  create segment n + 1  ->  publish it
    /// ```
    ///
    /// Segment n is durable before n + 1 exists, so only the newest segment can be torn.
    fn rotate(&mut self, shared: &Shared, counters: &Counters) -> Result<(), Error> {
        let synced = self.active.sync();
        self.check(synced)?;
        counters.record_sync();
        let hinted = Hint::write(&self.directory, self.active.id(), &self.active_records);
        self.check(hinted)?;

        // Four billion rotations of even 64-byte segments would take years of writes.
        let next_id = self
            .active
            .id()
            .checked_add(1)
            .ok_or_else(|| Error::Io(io::Error::other("segment identifiers exhausted")))?;
        let created = Segment::create(&self.directory, next_id);
        let next = Arc::new(self.check(created)?);

        // Readers must be able to open the new segment before any index entry names it.
        {
            let mut current = shared.write().unwrap_or_else(PoisonError::into_inner);
            Arc::make_mut(&mut current).add_segment(Arc::clone(&next));
        }
        self.ledger.open(next_id, 0);
        self.active = next;
        self.active_len = FILE_HEADER_LEN;
        self.active_records.clear();
        Ok(())
    }

    /// Refuses to write after an I/O failure.
    const fn ensure_healthy(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }

    /// Passes a result through, poisoning the log on failure.
    ///
    /// After a failed write or sync the kernel may have dropped dirty pages silently.
    /// Retrying could report success over lost data, so the only safe path is reopening.
    fn check<T>(&mut self, result: io::Result<T>) -> Result<T, Error> {
        result.map_err(|err| {
            self.poisoned = true;
            Error::Io(err)
        })
    }
}

impl Drop for Log {
    fn drop(&mut self) {
        // Close is a durability point under the manual policy.
        // Errors cannot be reported from a destructor; recovery covers a failed sync.
        if self.options.sync == SyncPolicy::Manual && !self.poisoned {
            drop(self.active.sync());
        }
    }
}
