//! The two staircases that answer surround-vote queries in logarithmic time.

use std::{collections::BTreeMap, ops::Bound};

use axiom_types::Epoch;

/// A vote is slashable when it surrounds, or is surrounded by, an earlier vote of its signer.
///
/// # Algorithm
///
/// Write a vote as its source and target epochs, (s, t).
/// A new vote (s, t) is slashable against a recorded (s', t') in two ways:
///
/// ```text
/// surrounded:   s' < s  and  t < t'
/// surrounding:  s < s'  and  t' < t
/// ```
///
/// The first asks for the minimum source over targets above t.
/// The second asks for the maximum source over targets below t.
///
/// Each query only needs a staircase of the recorded votes, not all of them.
///
/// - For the minimum above, keep a vote only if every higher target has a higher source.
/// - For the maximum below, keep a vote only if every lower target has a lower source.
///
/// In both staircases the sources rise strictly with the target.
/// The minimum above t is then the source of the first step above t.
/// The maximum below t is the source of the last step below t.
///
/// An insert removes the steps it dominates, and each vote is removed at most once.
/// Queries and inserts thus cost O(log n), amortised over the history.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SurroundIndex {
    /// Steps for the minimum source above a target, keyed by target.
    min_above: BTreeMap<Epoch, Epoch>,
    /// Steps for the maximum source below a target, keyed by target.
    max_below: BTreeMap<Epoch, Epoch>,
}

/// A recorded vote that a new vote would be slashable against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Surround {
    /// The recorded vote surrounds the new one.
    Surrounded {
        /// Source of the recorded vote.
        source: Epoch,
        /// Target of the recorded vote.
        target: Epoch,
    },
    /// The new vote surrounds the recorded one.
    Surrounding {
        /// Source of the recorded vote.
        source: Epoch,
        /// Target of the recorded vote.
        target: Epoch,
    },
}

impl SurroundIndex {
    /// The recorded vote a new vote would surround or be surrounded by, if any.
    pub(crate) fn find(&self, source: Epoch, target: Epoch) -> Option<Surround> {
        // The lowest source among targets above t sits at the first step above t.
        let above = self
            .min_above
            .range((Bound::Excluded(target), Bound::Unbounded))
            .next();
        if let Some((&recorded_target, &recorded_source)) = above
            && recorded_source < source
        {
            return Some(Surround::Surrounded {
                source: recorded_source,
                target: recorded_target,
            });
        }
        // The highest source among targets below t sits at the last step below t.
        let below = self.max_below.range(..target).next_back();
        if let Some((&recorded_target, &recorded_source)) = below
            && recorded_source > source
        {
            return Some(Surround::Surrounding {
                source: recorded_source,
                target: recorded_target,
            });
        }
        None
    }

    /// Records a vote.
    pub(crate) fn insert(&mut self, source: Epoch, target: Epoch) {
        Self::insert_min_above(&mut self.min_above, source, target);
        Self::insert_max_below(&mut self.max_below, source, target);
    }

    /// Adds a vote to the staircase of minimum sources above each target.
    fn insert_min_above(steps: &mut BTreeMap<Epoch, Epoch>, source: Epoch, target: Epoch) {
        // A higher target with a source no higher already answers every query this vote would.
        let dominated = steps
            .range(target..)
            .next()
            .is_some_and(|(_, &higher)| higher <= source);
        if dominated {
            return;
        }
        // Lower targets with a source no lower now never answer a query: drop them.
        let stale: Vec<Epoch> = steps
            .range(..target)
            .rev()
            .take_while(|(_, lower)| **lower >= source)
            .map(|(target, _)| *target)
            .collect();
        for target in stale {
            steps.remove(&target);
        }
        steps.insert(target, source);
    }

    /// Adds a vote to the staircase of maximum sources below each target.
    fn insert_max_below(steps: &mut BTreeMap<Epoch, Epoch>, source: Epoch, target: Epoch) {
        // A lower target with a source no lower already answers every query this vote would.
        let dominated = steps
            .range(..=target)
            .next_back()
            .is_some_and(|(_, &lower)| lower >= source);
        if dominated {
            return;
        }
        // Higher targets with a source no higher now never answer a query: drop them.
        let stale: Vec<Epoch> = steps
            .range((Bound::Excluded(target), Bound::Unbounded))
            .take_while(|(_, higher)| **higher <= source)
            .map(|(target, _)| *target)
            .collect();
        for target in stale {
            steps.remove(&target);
        }
        steps.insert(target, source);
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The slashable relation, straight from `is_slashable_attestation_data` minus double votes.
    fn brute_force(votes: &[(u64, u64)], source: u64, target: u64) -> bool {
        votes
            .iter()
            .any(|&(s, t)| (s < source && target < t) || (source < s && t < target))
    }

    #[test]
    fn a_vote_inside_a_recorded_span_is_surrounded() {
        // Fixture state: one vote from epoch 2 to epoch 10.
        let mut index = SurroundIndex::default();
        index.insert(Epoch(2), Epoch(10));

        // 3 to 9 sits strictly inside 2 to 10.
        assert_eq!(
            index.find(Epoch(3), Epoch(9)),
            Some(Surround::Surrounded {
                source: Epoch(2),
                target: Epoch(10),
            })
        );

        // 1 to 11 strictly contains it.
        assert_eq!(
            index.find(Epoch(1), Epoch(11)),
            Some(Surround::Surrounding {
                source: Epoch(2),
                target: Epoch(10),
            })
        );

        // Sharing an endpoint is not a surround: 2 to 9 and 3 to 10 pass.
        assert_eq!(index.find(Epoch(2), Epoch(9)), None);
        assert_eq!(index.find(Epoch(3), Epoch(10)), None);
    }

    proptest! {
        #[test]
        fn the_index_agrees_with_a_scan_of_every_vote(
            votes in prop::collection::vec((0_u64..40, 0_u64..40), 0..60),
            queries in prop::collection::vec((0_u64..40, 0_u64..40), 1..40),
        ) {
            // Any history, honest or not, and any query: the staircases see what a scan sees.
            let mut index = SurroundIndex::default();
            let mut recorded = Vec::new();
            for (a, b) in votes {
                let (source, target) = (a.min(b), a.max(b));
                index.insert(Epoch(source), Epoch(target));
                recorded.push((source, target));
            }
            for (a, b) in queries {
                let (source, target) = (a.min(b), a.max(b));
                prop_assert_eq!(
                    index.find(Epoch(source), Epoch(target)).is_some(),
                    brute_force(&recorded, source, target)
                );
            }
        }
    }
}
