//! Tuning knobs fixed when a store opens.

use crate::Error;

/// When committed batches reach stable storage.
///
/// A write always reaches the operating system before it returns.
/// A process crash therefore never loses a committed batch.
/// This policy only decides what survives a power loss or kernel crash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyncPolicy {
    /// Flush every batch to stable storage before the write returns.
    ///
    /// A returned write survives power loss.
    /// Each commit pays one device flush, about 0.1 to 10 ms depending on the drive.
    #[default]
    EveryBatch,

    /// Flush only on segment rotation, compaction, close, or an explicit sync.
    ///
    /// Power loss may drop recent batches, but always a suffix of whole batches.
    /// Recovery never exposes a partial batch.
    Manual,
}

/// Configuration of a store on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// Durability of each committed batch.
    pub sync: SyncPolicy,

    /// Size in bytes past which the active segment is sealed and a new one starts.
    ///
    /// Compaction works one segment at a time, so this is also its granularity.
    /// A batch never spans two segments, so one large batch may overshoot the size.
    pub segment_size: u64,

    /// Share of dead bytes, in percent, that makes a sealed segment worth rewriting.
    ///
    /// Zero rewrites every sealed segment on each compaction.
    /// One hundred rewrites only segments with no live record left.
    pub compaction_threshold: u8,

    /// Whether sealing a segment triggers a compaction pass right away.
    ///
    /// Turn it off to schedule compaction from the caller, for example after finalization.
    pub auto_compact: bool,
}

impl Options {
    /// Smallest accepted segment size.
    ///
    /// A segment must at least hold its file header and one frame header.
    pub const MIN_SEGMENT_SIZE: u64 = 64;

    /// Checks every bound documented on the fields.
    pub(crate) const fn validate(&self) -> Result<(), Error> {
        if self.segment_size < Self::MIN_SEGMENT_SIZE {
            return Err(Error::SegmentSizeTooSmall {
                size: self.segment_size,
            });
        }
        if self.compaction_threshold > 100 {
            return Err(Error::CompactionThresholdTooHigh {
                threshold: self.compaction_threshold,
            });
        }
        Ok(())
    }
}

impl Default for Options {
    /// Durable commits, 256 MiB segments, and automatic compaction at half garbage.
    ///
    /// - 256 MiB holds a mainnet beacon state, so a state rarely straddles a rotation.
    /// - Rewriting at 50% garbage bounds space amplification by two.
    /// - Each rewritten live byte then pays for at least one reclaimed dead byte.
    fn default() -> Self {
        Self {
            sync: SyncPolicy::EveryBatch,
            segment_size: 256 << 20,
            compaction_threshold: 50,
            auto_compact: true,
        }
    }
}
