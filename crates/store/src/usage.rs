//! Live and dead byte accounting per segment.

use std::collections::BTreeMap;

use crate::slot::Slot;

/// How much of a segment still matters.
///
/// An entry is live while the index points at it.
/// Overwritten values, deleted values and tombstones are dead.
/// Frame headers count as dead too: compaction never copies them as they are.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Usage {
    /// Bytes of frames, everything after the file header.
    pub(crate) total: u64,
    /// Bytes of entries the index points at.
    pub(crate) live: u64,
}

impl Usage {
    /// Returns the bytes compaction would reclaim.
    pub(crate) const fn dead(self) -> u64 {
        self.total - self.live
    }

    /// Returns whether the dead share reaches a threshold in percent.
    ///
    /// A segment holding no frame at all always qualifies: deleting it costs nothing.
    pub(crate) const fn is_garbage(self, threshold: u8) -> bool {
        //     dead / total >= threshold / 100
        // <=> dead * 100 >= threshold * total, exact in integers.
        //
        // Bound: total < 2^56 for any real disk, so the products fit in u64 with room to spare.
        self.total == 0 || self.dead() * 100 >= threshold as u64 * self.total
    }
}

/// The usage of every segment, kept in step with the index.
///
/// Every index change moves bytes between live and dead.
/// Keeping the tally incrementally makes compaction planning O(segments), with no disk access.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Ledger {
    /// Usage per segment identifier.
    segments: BTreeMap<u32, Usage>,
}

impl Ledger {
    /// Starts tracking a segment holding a given number of frame bytes.
    pub(crate) fn open(&mut self, segment: u32, total: u64) {
        self.segments.insert(segment, Usage { total, live: 0 });
    }

    /// Stops tracking a segment, returning its last usage.
    pub(crate) fn close(&mut self, segment: u32) -> Usage {
        self.segments.remove(&segment).unwrap_or_default()
    }

    /// Returns the usage of a segment.
    pub(crate) fn usage(&self, segment: u32) -> Usage {
        self.segments.get(&segment).copied().unwrap_or_default()
    }

    /// Iterates segments in identifier order with their usage.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (u32, Usage)> + '_ {
        self.segments.iter().map(|(&id, &usage)| (id, usage))
    }

    /// Records frame bytes appended to a segment.
    pub(crate) fn grow(&mut self, segment: u32, bytes: u64) {
        if let Some(usage) = self.segments.get_mut(&segment) {
            usage.total += bytes;
        }
    }

    /// Records an index change: the displaced slot dies, the new disk slot comes alive.
    pub(crate) fn exchange(
        &mut self,
        key_len: usize,
        displaced: Option<&Slot>,
        added: Option<&Slot>,
    ) {
        if let Some(Slot::Disk(location)) = displaced
            && let Some(usage) = self.segments.get_mut(&location.segment)
        {
            usage.live -= location.entry_len(key_len);
        }
        if let Some(Slot::Disk(location)) = added
            && let Some(usage) = self.segments.get_mut(&location.segment)
        {
            usage.live += location.entry_len(key_len);
        }
    }

    /// Returns the number of segments, their total size, and their live bytes.
    pub(crate) fn totals(&self) -> (u64, u64, u64) {
        self.segments
            .values()
            .fold((0, 0, 0), |(count, total, live), usage| {
                (count + 1, total + usage.total, live + usage.live)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot::Location;

    #[test]
    fn ledger_moves_bytes_between_live_and_dead() {
        // Fixture state: segments 0 and 1, each holding 100 frame bytes.
        let mut ledger = Ledger::default();
        ledger.open(0, 100);
        ledger.open(1, 100);

        // A 4-byte key with a 10-byte value: 12 + 4 + 10 = 26 bytes per entry.
        let in_zero = Slot::Disk(Location {
            segment: 0,
            value_len: 10,
            offset: 16,
        });
        let in_one = Slot::Disk(Location {
            segment: 1,
            value_len: 10,
            offset: 16,
        });

        // Put into segment 0: 26 live bytes there.
        ledger.exchange(4, None, Some(&in_zero));
        assert_eq!(
            ledger.usage(0),
            Usage {
                total: 100,
                live: 26
            }
        );

        // Overwrite into segment 1: segment 0 drops back to 0 live, segment 1 gains 26.
        ledger.exchange(4, Some(&in_zero), Some(&in_one));
        assert_eq!(
            ledger.usage(0),
            Usage {
                total: 100,
                live: 0
            }
        );
        assert_eq!(
            ledger.usage(1),
            Usage {
                total: 100,
                live: 26
            }
        );

        // In-memory slots are not on disk and change nothing.
        ledger.exchange(4, Some(&Slot::Memory(b"v".as_slice().into())), None);
        assert_eq!(ledger.totals(), (2, 200, 26));

        // Closing segment 0 hands back its final usage.
        assert_eq!(
            ledger.close(0),
            Usage {
                total: 100,
                live: 0
            }
        );
        assert_eq!(ledger.totals(), (1, 100, 26));
    }

    #[test]
    fn garbage_threshold_is_inclusive() {
        // 50 dead bytes out of 100.
        let usage = Usage {
            total: 100,
            live: 50,
        };
        assert_eq!(usage.dead(), 50);
        // Exactly at 50 percent: qualifies.
        assert!(usage.is_garbage(50));
        // One percent above: does not.
        assert!(!usage.is_garbage(51));
        // Threshold 0 selects even a fully live segment.
        assert!(
            Usage {
                total: 100,
                live: 100
            }
            .is_garbage(0)
        );
        // An empty segment always qualifies, even at 100 percent.
        assert!(Usage::default().is_garbage(100));
    }
}
