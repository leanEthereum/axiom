//! How much past state the database keeps: the storage modes and the snapshot cadence.

use std::{fmt, num::NonZeroU64, str::FromStr};

use axiom_types::Slot;
use thiserror::Error;

/// Slots between two state snapshots in archive mode.
///
/// A lookup replays at most one interval of blocks, so the interval trades disk for latency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotInterval(NonZeroU64);

impl SnapshotInterval {
    /// One snapshot every 64 mainnet epochs.
    ///
    /// A full mainnet state weighs a few hundred megabytes.
    /// At this cadence the snapshots grow by about a gigabyte a day.
    /// A lookup then replays at most 2047 blocks, without their signatures.
    pub const DEFAULT: Self = Self(NonZeroU64::new(2048).expect("2048 is not zero"));

    /// An interval of some slots, or nothing for zero slots.
    #[must_use]
    pub const fn new(slots: u64) -> Option<Self> {
        match NonZeroU64::new(slots) {
            Some(slots) => Some(Self(slots)),
            None => None,
        }
    }

    /// Slots in the interval.
    #[must_use]
    pub const fn slots(self) -> u64 {
        self.0.get()
    }

    /// Whether a snapshot falls on a slot.
    #[must_use]
    pub const fn is_due(self, slot: Slot) -> bool {
        slot.0 % self.0.get() == 0
    }
}

impl Default for SnapshotInterval {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for SnapshotInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for SnapshotInterval {
    type Err = InvalidInterval;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.parse()
            .ok()
            .and_then(Self::new)
            .ok_or_else(|| InvalidInterval(text.to_owned()))
    }
}

/// A snapshot interval that is not a positive whole number of slots.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("snapshot interval {0:?} is not a positive number of slots")]
pub struct InvalidInterval(pub String);

/// How much history the database keeps.
///
/// Blocks are kept in every mode, back to where backfill stops.
/// Blob and column sidecars are pruned past their retention windows in every mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum StorageMode {
    /// Only the latest finalized state, the anchor a restart resumes from.
    ///
    /// Backfill stops at the window peers must serve blocks for.
    #[default]
    Pruned,
    /// Periodic state snapshots as well, so the state at any slot can be rebuilt.
    ///
    /// Backfill runs to genesis, and replay rebuilds a state from the nearest snapshot.
    Archive(SnapshotInterval),
}

impl StorageMode {
    /// The snapshot cadence, in archive mode only.
    #[must_use]
    pub const fn interval(self) -> Option<SnapshotInterval> {
        match self {
            Self::Pruned => None,
            Self::Archive(interval) => Some(interval),
        }
    }

    /// Whether backfill continues past the serving window, down to genesis.
    #[must_use]
    pub const fn backfills_to_genesis(self) -> bool {
        matches!(self, Self::Archive(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_interval_is_a_positive_slot_count() {
        assert_eq!(SnapshotInterval::new(0), None);
        assert_eq!("0".parse::<SnapshotInterval>(), Err(InvalidInterval("0".to_owned())));
        assert_eq!(
            "eight".parse::<SnapshotInterval>(),
            Err(InvalidInterval("eight".to_owned()))
        );
        assert_eq!("64".parse::<SnapshotInterval>(), Ok(SnapshotInterval::new(64).unwrap()));
        assert_eq!(SnapshotInterval::default().slots(), 2048);
    }

    #[test]
    fn snapshots_fall_on_multiples_of_the_interval() {
        // Interval 8: slots 0, 8, 16 get a snapshot; 7 and 9 do not.
        let interval = SnapshotInterval::new(8).unwrap();
        let due: Vec<u64> = (0..18).filter(|slot| interval.is_due(Slot(*slot))).collect();
        assert_eq!(due, [0, 8, 16]);
    }

    #[test]
    fn only_the_archive_mode_snapshots_and_backfills_to_genesis() {
        let interval = SnapshotInterval::new(32).unwrap();
        assert_eq!(StorageMode::Pruned.interval(), None);
        assert!(!StorageMode::Pruned.backfills_to_genesis());
        assert_eq!(StorageMode::Archive(interval).interval(), Some(interval));
        assert!(StorageMode::Archive(interval).backfills_to_genesis());
    }
}
