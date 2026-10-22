//! Which segments compaction rewrites, and which of their entries survive.
//!
//! # Overview
//!
//! An append-only log never overwrites, so dead entries pile up.
//! Compaction picks sealed segments that are mostly dead.
//! It copies their live entries to the end of the log, then deletes them.
//!
//! ```text
//!     before:  | seg 3: a1 b1 c1 | seg 4: a2 x1 | seg 5 (active): b2 |
//!                       ^dead ^dead       ^live                ^live
//!              seg 3 is 2/3 dead: rewrite it, c1 is its only live entry
//!
//!     after:   | seg 4: a2 x1 | seg 5 (active): b2 c1' |
//! ```
//!
//! Live puts are easy: the index points at exactly one entry per key.
//!
//! Tombstones are subtle.
//! A tombstone is dead weight unless an older segment still holds a put of its key.
//! Dropping it would let that put win again at the next replay, resurrecting the key.
//!
//! ```text
//!     seg 1: put k=v   (not compacted, mostly live)
//!     seg 2: del k     (compacted)
//!     drop the tombstone -> replay sees seg 1 only -> k=v is back
//! ```
//!
//! Finding the exact older segments holding the key would need their hints.
//! The plan keeps a tombstone when any segment older than its own survives, and its key is still absent.
//! That is conservative and costs a few small entries.
//!
//! # Invariants
//!
//! Copies land in segments newer than every victim, so at replay they win over the originals.
//! Victims are deleted only after the copies are durable.
//! A crash in between leaves duplicates, never a loss, and the next compaction removes them.
//!
//! Victims are deleted oldest first.
//! A crash mid-deletion then leaves the newest victims, never a put without its tombstone.

use crate::{format::Kind, record::Record, slot::Slot, usage::Ledger, version::Version};

/// The segments one compaction pass rewrites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Segments to rewrite, oldest first.
    victims: Vec<u32>,
    /// The oldest sealed segment that survives the pass.
    oldest_survivor: Option<u32>,
}

impl Plan {
    /// Selects every sealed segment whose dead share reaches the threshold.
    pub(crate) fn select(ledger: &Ledger, active: u32, threshold: u8) -> Self {
        let mut victims = Vec::new();
        let mut oldest_survivor = None;
        // The ledger iterates in identifier order, so victims come out sorted.
        for (id, usage) in ledger.iter().filter(|&(id, _)| id != active) {
            if usage.is_garbage(threshold) {
                victims.push(id);
            } else if oldest_survivor.is_none() {
                oldest_survivor = Some(id);
            }
        }
        Self {
            victims,
            oldest_survivor,
        }
    }

    /// Returns the segments to rewrite, oldest first.
    pub(crate) fn victims(&self) -> &[u32] {
        &self.victims
    }

    /// Returns whether an entry of a victim must be copied forward.
    pub(crate) fn retains(&self, victim: u32, record: &Record, version: &Version) -> bool {
        let current = version.slot(record.table, &record.key);
        match record.kind {
            // A put survives only if the index still points at this very entry.
            Kind::Put => current == Some(&Slot::Disk(record.location(victim))),
            // A tombstone survives if the key is still absent and an older put may remain.
            Kind::Delete => {
                current.is_none() && self.oldest_survivor.is_some_and(|oldest| oldest < victim)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot::Location;

    #[test]
    fn selection_skips_the_active_segment_and_live_segments() {
        // Fixture state, threshold 50 percent:
        //
        //     seg 0: 100 bytes, 90 live  -> 10% dead, survives
        //     seg 1: 100 bytes, 20 live  -> 80% dead, victim
        //     seg 2: 100 bytes,  0 live  -> active, never a victim
        let mut ledger = Ledger::default();
        ledger.open(0, 100);
        ledger.open(1, 100);
        ledger.open(2, 100);
        let live = |segment, value_len| {
            Slot::Disk(Location {
                segment,
                value_len,
                offset: 16,
            })
        };
        // Entries of 12 + 0 + value_len bytes make the live counts exact.
        ledger.exchange(0, None, Some(&live(0, 78)));
        ledger.exchange(0, None, Some(&live(1, 8)));

        let plan = Plan::select(&ledger, 2, 50);
        assert_eq!(
            plan,
            Plan {
                victims: vec![1],
                oldest_survivor: Some(0),
            }
        );
    }

    #[test]
    fn tombstones_survive_only_above_an_older_survivor() {
        // Fixture state: table 1 is empty, so every key is absent.
        let mut version = Version::new();
        version.apply(0, &[1, b't'], Some(Slot::Memory(Vec::new().into())));
        let tombstone = Record {
            kind: Kind::Delete,
            table: 1,
            key: b"k".to_vec().into_boxed_slice(),
            value_len: 0,
            offset: 16,
        };

        // Survivor 0 is older than victim 1: the tombstone may shadow a put in segment 0.
        let plan = Plan {
            victims: vec![1],
            oldest_survivor: Some(0),
        };
        assert!(plan.retains(1, &tombstone, &version));

        // No survivor older than victim 1: nothing left to shadow, drop it.
        let plan = Plan {
            victims: vec![1],
            oldest_survivor: Some(2),
        };
        assert!(!plan.retains(1, &tombstone, &version));

        // The key was put again after the tombstone: the tombstone is obsolete.
        let mut version = version;
        version.apply(1, b"k", Some(Slot::Memory(b"v".as_slice().into())));
        let plan = Plan {
            victims: vec![1],
            oldest_survivor: Some(0),
        };
        assert!(!plan.retains(1, &tombstone, &version));
    }

    #[test]
    fn puts_survive_only_where_the_index_points() {
        // Fixture state: key "k" of table 1 lives in segment 3 at offset 40.
        let mut version = Version::new();
        version.apply(0, &[1, b't'], Some(Slot::Memory(Vec::new().into())));
        let here = Location {
            segment: 3,
            value_len: 5,
            offset: 40,
        };
        version.apply(1, b"k", Some(Slot::Disk(here)));
        let plan = Plan {
            victims: vec![3],
            oldest_survivor: None,
        };
        let mut record = Record {
            kind: Kind::Put,
            table: 1,
            key: b"k".to_vec().into_boxed_slice(),
            value_len: 5,
            offset: 40,
        };

        // The entry at offset 40 is the live one.
        assert!(plan.retains(3, &record, &version));

        // Mutation: an older put of the same key at offset 16 is dead.
        record.offset = 16;
        assert!(!plan.retains(3, &record, &version));
    }
}
