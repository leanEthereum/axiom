//! Sets of integers stored as disjoint half-open ranges.
//!
//! Acknowledgments, stream reassembly and retransmission all track sets of packet numbers or offsets.
//! Such sets are mostly long runs with a few gaps, so ranges store them compactly.

use std::{collections::BTreeMap, ops::Range};

/// A set of u64 values as disjoint, non-adjacent ranges, ordered by start.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RangeSet {
    /// Start to end of each range; ends are exclusive.
    ranges: BTreeMap<u64, u64>,
}

impl RangeSet {
    /// The empty set.
    pub(crate) const fn new() -> Self {
        Self {
            ranges: BTreeMap::new(),
        }
    }

    /// Whether the set is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Ranges in the set.
    pub(crate) fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// The smallest value.
    pub(crate) fn min(&self) -> Option<u64> {
        self.ranges.first_key_value().map(|(start, _)| *start)
    }

    /// Whether a value is in the set.
    pub(crate) fn contains(&self, value: u64) -> bool {
        self.ranges
            .range(..=value)
            .next_back()
            .is_some_and(|(_, end)| value < *end)
    }

    /// Adds a range, merging with neighbours it touches.
    ///
    /// # Returns
    ///
    /// Whether any value was new.
    pub(crate) fn insert(&mut self, range: Range<u64>) -> bool {
        if range.is_empty() {
            return false;
        }
        // Invariant: ranges never touch, so a covered range lies inside a single stored one.
        let (mut start, mut end) = (range.start, range.end);
        if let Some((&prev_start, &prev_end)) = self.ranges.range(..=start).next_back()
            && prev_end >= start
        {
            if prev_end >= end {
                return false;
            }
            start = prev_start;
            self.ranges.remove(&prev_start);
        }
        // Absorb every range that starts inside ours or right at its end.
        while let Some((&next_start, &next_end)) = self.ranges.range(start..=end).next() {
            end = end.max(next_end);
            self.ranges.remove(&next_start);
        }
        self.ranges.insert(start, end);
        true
    }

    /// Removes a range.
    pub(crate) fn remove(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        // Split a range that starts before ours and overlaps it.
        if let Some((&prev_start, &prev_end)) = self.ranges.range(..range.start).next_back()
            && prev_end > range.start
        {
            self.ranges.insert(prev_start, range.start);
            if prev_end > range.end {
                self.ranges.insert(range.end, prev_end);
                return;
            }
        }
        // Trim or drop every range that starts inside ours.
        while let Some((&next_start, &next_end)) = self.ranges.range(range.start..range.end).next()
        {
            self.ranges.remove(&next_start);
            if next_end > range.end {
                self.ranges.insert(range.end, next_end);
                break;
            }
        }
    }

    /// Removes and returns the lowest range.
    pub(crate) fn pop_min(&mut self) -> Option<Range<u64>> {
        self.ranges.pop_first().map(|(start, end)| start..end)
    }

    /// Drops every value below a bound.
    pub(crate) fn remove_below(&mut self, bound: u64) {
        self.remove(0..bound);
    }

    /// Ranges in ascending order.
    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = Range<u64>> + '_ {
        self.ranges.iter().map(|(start, end)| *start..*end)
    }

    /// The parts of a range not in the set, in ascending order.
    pub(crate) fn gaps(&self, range: Range<u64>) -> Vec<Range<u64>> {
        let mut gaps = Vec::new();
        let mut cursor = range.start;
        let first = self
            .ranges
            .range(..=range.start)
            .next_back()
            .map_or(range.start, |(start, _)| *start);
        for (&start, &end) in self.ranges.range(first..range.end) {
            if start > cursor {
                gaps.push(cursor..start.min(range.end));
            }
            cursor = cursor.max(end);
            if cursor >= range.end {
                break;
            }
        }
        if cursor < range.end {
            gaps.push(cursor..range.end);
        }
        gaps
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn merges_and_splits() {
        let mut set = RangeSet::new();
        assert!(set.insert(0..5));
        assert!(set.insert(10..15));
        // Touching at 5 merges, overlap at 9..11 bridges into one range.
        assert!(set.insert(5..11));
        assert_eq!(set.iter().next(), Some(0..15));
        assert_eq!(set.range_count(), 1);
        // Fully covered: nothing new.
        assert!(!set.insert(3..7));

        // Removing the middle splits; removing a prefix trims.
        set.remove(4..6);
        assert_eq!(set.iter().collect::<Vec<_>>(), [0..4, 6..15]);
        set.remove_below(2);
        assert_eq!(set.iter().collect::<Vec<_>>(), [2..4, 6..15]);
        assert_eq!(set.min(), Some(2));
        assert!(set.contains(3) && !set.contains(4) && set.contains(14) && !set.contains(15));
        assert_eq!(set.gaps(0..20), [0..2, 4..6, 15..20]);
        assert_eq!(set.pop_min(), Some(2..4));
        assert_eq!(set.range_count(), 1);
    }

    proptest! {
        #[test]
        fn matches_a_plain_set(
            ops in proptest::collection::vec((any::<bool>(), 0_u64..64, 0_u64..16), 0..40),
        ) {
            let mut set = RangeSet::new();
            let mut model = BTreeSet::new();
            for (insert, start, len) in ops {
                let range = start..start + len;
                if insert {
                    let new = range.clone().any(|v| !model.contains(&v));
                    prop_assert_eq!(set.insert(range.clone()), new);
                    model.extend(range);
                } else {
                    set.remove(range.clone());
                    for value in range {
                        model.remove(&value);
                    }
                }
                // Ranges stay disjoint and non-adjacent, and hold exactly the model.
                let ranges: Vec<_> = set.iter().collect();
                for pair in ranges.windows(2) {
                    prop_assert!(pair[0].end < pair[1].start);
                }
                let flat: BTreeSet<u64> = ranges.into_iter().flatten().collect();
                prop_assert_eq!(&flat, &model);
                let gaps: BTreeSet<u64> = set.gaps(0..80).into_iter().flatten().collect();
                let missing: BTreeSet<u64> = (0..80).filter(|v| !model.contains(v)).collect();
                prop_assert_eq!(gaps, missing);
            }
        }
    }
}
