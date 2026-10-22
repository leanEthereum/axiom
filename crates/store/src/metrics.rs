//! Operation counters, readable without a logging or metrics framework.

use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic counters shared by the store and its snapshots.
///
/// Relaxed atomics suffice: each counter is independent and only ever summed.
#[derive(Debug, Default)]
pub(crate) struct Counters {
    /// Bytes appended to segment files, frames and compaction copies included.
    bytes_written: AtomicU64,
    /// Bytes of entries read to serve values.
    bytes_read: AtomicU64,
    /// Batches committed.
    batches: AtomicU64,
    /// Flushes to stable storage.
    syncs: AtomicU64,
    /// Compaction passes that rewrote at least one segment.
    compactions: AtomicU64,
    /// Bytes of disk space freed by compaction.
    bytes_reclaimed: AtomicU64,
}

impl Counters {
    /// Counts one committed batch of a given encoded size.
    pub(crate) fn record_batch(&self, bytes: u64) {
        self.batches.fetch_add(1, Ordering::Relaxed);
        self.record_write(bytes);
    }

    /// Counts bytes appended to a segment.
    pub(crate) fn record_write(&self, bytes: u64) {
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Counts bytes read to serve a value.
    pub(crate) fn record_read(&self, bytes: u64) {
        self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Counts one flush to stable storage.
    pub(crate) fn record_sync(&self) {
        self.syncs.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one compaction pass and the space it freed.
    pub(crate) fn record_compaction(&self, reclaimed: u64) {
        self.compactions.fetch_add(1, Ordering::Relaxed);
        self.bytes_reclaimed.fetch_add(reclaimed, Ordering::Relaxed);
    }

    /// Reads every counter, adding the current disk usage.
    pub(crate) fn snapshot(&self, segments: u64, disk_bytes: u64, live_bytes: u64) -> Metrics {
        Metrics {
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            batches: self.batches.load(Ordering::Relaxed),
            syncs: self.syncs.load(Ordering::Relaxed),
            compactions: self.compactions.load(Ordering::Relaxed),
            bytes_reclaimed: self.bytes_reclaimed.load(Ordering::Relaxed),
            segments,
            disk_bytes,
            live_bytes,
        }
    }
}

/// A point-in-time reading of the store's counters and disk usage.
///
/// Counters start at zero when the store opens; they are not persisted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    /// Bytes appended to segment files.
    bytes_written: u64,
    /// Bytes of entries read to serve values.
    bytes_read: u64,
    /// Batches committed.
    batches: u64,
    /// Flushes to stable storage.
    syncs: u64,
    /// Compaction passes that rewrote at least one segment.
    compactions: u64,
    /// Bytes of disk space freed by compaction.
    bytes_reclaimed: u64,
    /// Segment files on disk.
    segments: u64,
    /// Bytes of frames across all segments.
    disk_bytes: u64,
    /// Bytes of entries the index points at.
    live_bytes: u64,
}

impl Metrics {
    /// Returns the bytes appended to segment files, compaction copies included.
    #[must_use]
    pub const fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Returns the bytes of entries read to serve values.
    #[must_use]
    pub const fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Returns the number of committed batches.
    #[must_use]
    pub const fn batches(&self) -> u64 {
        self.batches
    }

    /// Returns the number of flushes to stable storage.
    #[must_use]
    pub const fn syncs(&self) -> u64 {
        self.syncs
    }

    /// Returns the number of compaction passes that rewrote at least one segment.
    #[must_use]
    pub const fn compactions(&self) -> u64 {
        self.compactions
    }

    /// Returns the bytes of disk space freed by compaction.
    #[must_use]
    pub const fn bytes_reclaimed(&self) -> u64 {
        self.bytes_reclaimed
    }

    /// Returns the number of segment files on disk.
    #[must_use]
    pub const fn segments(&self) -> u64 {
        self.segments
    }

    /// Returns the bytes of frames across all segments, excluding file headers.
    #[must_use]
    pub const fn disk_bytes(&self) -> u64 {
        self.disk_bytes
    }

    /// Returns the bytes of entries still reachable through the index.
    ///
    /// The ratio of disk bytes to live bytes is the space amplification.
    #[must_use]
    pub const fn live_bytes(&self) -> u64 {
        self.live_bytes
    }
}
