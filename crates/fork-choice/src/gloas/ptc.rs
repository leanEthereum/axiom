//! The payload timeliness committee's votes on each block's payload.

use std::collections::HashMap;

use axiom_types::{Preset, Root};

use crate::BlockNode;

/// One block's committee votes, one seat per entry, unset until the seat votes.
///
/// A validator may hold several seats, and its vote fills each of them.
/// See `payload_timeliness_vote` in the Gloas fork choice store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadVotes {
    /// Per seat, whether the payload arrived in time.
    pub timely: Vec<Option<bool>>,
    /// Per seat, whether the blob data was available.
    pub available: Vec<Option<bool>>,
}

impl PayloadVotes {
    /// Votes of a committee of a size, before any seat has voted.
    fn empty(size: usize) -> Self {
        Self {
            timely: vec![None; size],
            available: vec![None; size],
        }
    }

    /// Whether more than half the seats agree on a timeliness verdict.
    ///
    /// Threshold: strictly more than half the committee, so a split vote decides nothing.
    /// See `payload_timeliness` and `PAYLOAD_TIMELY_THRESHOLD` in the Gloas fork choice spec.
    #[must_use]
    pub fn timeliness_reaches(&self, timely: bool) -> bool {
        Self::majority(&self.timely, timely)
    }

    /// Whether more than half the seats agree on a data availability verdict.
    ///
    /// See `payload_data_availability` and `DATA_AVAILABILITY_TIMELY_THRESHOLD` in the Gloas spec.
    #[must_use]
    pub fn availability_reaches(&self, available: bool) -> bool {
        Self::majority(&self.available, available)
    }

    /// Whether more than half the seats voted a verdict.
    fn majority(seats: &[Option<bool>], verdict: bool) -> bool {
        let agreeing = seats.iter().filter(|seat| **seat == Some(verdict)).count();
        agreeing > seats.len() / 2
    }
}

/// Every Gloas block's committee votes, by block root.
///
/// Blocks from before Gloas carry their payload, and the committee never votes on them.
#[derive(Clone, Debug, Default)]
pub struct PtcVotes {
    /// Votes by block root.
    blocks: HashMap<Root, PayloadVotes>,
}

impl PtcVotes {
    /// Opens the votes of a new block, every seat unset.
    pub fn open<P: Preset>(&mut self, root: Root) {
        self.blocks
            .entry(root)
            .or_insert_with(|| PayloadVotes::empty(P::PTC_SIZE as usize));
    }

    /// The votes on a block, if the committee votes on it.
    #[must_use]
    pub fn of(&self, root: &Root) -> Option<&PayloadVotes> {
        self.blocks.get(root)
    }

    /// Whether a block's payload counts as timely, or as late when asked for that verdict.
    ///
    /// A payload not verified locally is never timely, whatever the committee says.
    /// See `payload_timeliness` in the Gloas fork choice spec.
    #[must_use]
    pub fn payload_timeliness(&self, root: &Root, block: &BlockNode, timely: bool) -> bool {
        if !block.is_payload_verified() {
            return !timely;
        }
        self.of(root)
            .is_some_and(|votes| votes.timeliness_reaches(timely))
    }

    /// Whether a block's blob data counts as available, or as missing when asked for that verdict.
    ///
    /// A payload not verified locally never has its data available.
    /// See `payload_data_availability` in the Gloas fork choice spec.
    #[must_use]
    pub fn payload_data_availability(
        &self,
        root: &Root,
        block: &BlockNode,
        available: bool,
    ) -> bool {
        if !block.is_payload_verified() {
            return !available;
        }
        self.of(root)
            .is_some_and(|votes| votes.availability_reaches(available))
    }

    /// Records one member's vote in each of its seats.
    ///
    /// See `on_payload_attestation_message` in the Gloas fork choice spec.
    pub fn record(&mut self, root: Root, seats: &[usize], timely: bool, available: bool) {
        if let Some(votes) = self.blocks.get_mut(&root) {
            for seat in seats {
                if let Some(entry) = votes.timely.get_mut(*seat) {
                    *entry = Some(timely);
                }
                if let Some(entry) = votes.available.get_mut(*seat) {
                    *entry = Some(available);
                }
            }
        }
    }

    /// Forgets the votes on blocks that left the store.
    pub fn forget(&mut self, root: &Root) {
        self.blocks.remove(root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verdict_needs_more_than_half_the_seats() {
        // Fixture state: a committee of 4 seats.
        let mut votes = PayloadVotes::empty(4);

        // 2 of 4 timely votes is exactly half: no verdict either way.
        votes.timely = vec![Some(true), Some(true), None, None];
        assert!(!votes.timeliness_reaches(true));
        assert!(!votes.timeliness_reaches(false));

        // 3 of 4 is a majority.
        votes.timely[2] = Some(true);
        assert!(votes.timeliness_reaches(true));
    }

    #[test]
    fn a_member_votes_in_each_of_its_seats() {
        // Fixture state: one block, a committee of 4, and a member holding seats 1 and 3.
        let mut ptc = PtcVotes::default();
        let root = Root([1; 32]);
        ptc.blocks.insert(root, PayloadVotes::empty(4));

        ptc.record(root, &[1, 3], true, false);

        let votes = ptc.of(&root).unwrap();
        assert_eq!(votes.timely, [None, Some(true), None, Some(true)]);
        assert_eq!(votes.available, [None, Some(false), None, Some(false)]);
    }
}
