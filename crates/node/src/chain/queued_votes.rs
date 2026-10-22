//! Votes that arrived during their own slot, held until the fork choice may count them.

use std::collections::VecDeque;

use axiom_types::{Slot, vote::CommitteeVote};

/// Most votes held at once.
///
/// Votes arrive one per attester and slot, and are held one slot.
/// A mainnet slot has some 31,000 attesters, so this holds two slots of them.
const MAX_QUEUED_VOTES: usize = 1 << 16;

/// Votes of the current slot, waiting for the next one.
///
/// # Overview
///
/// A vote only counts in the fork choice from the slot after its own.
/// Gossip still delivers it during its own slot, when its weight matters most a slot later.
/// Holding it rather than dropping it lets the next slot's head and reorg checks see it.
///
/// The fork choice rechecks each vote when it is released, signature included.
/// See `validate_on_attestation` in the phase0 fork choice spec, and the attestation topic rules.
#[derive(Clone, Debug, Default)]
pub(crate) struct QueuedVotes {
    /// Held votes, oldest first.
    votes: VecDeque<CommitteeVote>,
}

impl QueuedVotes {
    /// Holds a vote, dropping the oldest one when full.
    pub(crate) fn push(&mut self, vote: CommitteeVote) {
        if self.votes.len() == MAX_QUEUED_VOTES {
            self.votes.pop_front();
        }
        self.votes.push_back(vote);
    }

    /// Releases every vote cast before a slot, keeping the others.
    pub(crate) fn release(&mut self, current: Slot) -> Vec<CommitteeVote> {
        let (due, waiting) = self
            .votes
            .drain(..)
            .partition(|vote| vote.data.slot < current);
        self.votes = waiting;
        due.into()
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{BlsSignature, phase0::AttestationData, vote::PayloadClaim};

    use super::*;

    fn vote(slot: u64) -> CommitteeVote {
        CommitteeVote {
            data: AttestationData {
                slot: Slot(slot),
                ..AttestationData::default()
            },
            signature: BlsSignature::default(),
            committees: Vec::new(),
            bits: Vec::new(),
            payload: PayloadClaim::Silent,
        }
    }

    #[test]
    fn votes_are_released_once_their_slot_has_passed() {
        // Fixture state: votes of slots 4, 5, and 5 held during slot 5.
        let mut queued = QueuedVotes::default();
        queued.push(vote(4));
        queued.push(vote(5));
        queued.push(vote(5));

        // At slot 5, only the slot 4 vote may count.
        assert_eq!(queued.release(Slot(5)), vec![vote(4)]);

        // At slot 6, both slot 5 votes are released, and nothing stays held.
        assert_eq!(queued.release(Slot(6)), vec![vote(5), vote(5)]);
        assert_eq!(queued.release(Slot(7)), Vec::new());
    }

    #[test]
    fn a_full_queue_drops_its_oldest_vote() {
        // Fixture state: the queue is full of slot 1 votes, then one slot 2 vote arrives.
        let mut queued = QueuedVotes::default();
        for _ in 0..MAX_QUEUED_VOTES {
            queued.push(vote(1));
        }
        queued.push(vote(2));

        // One slot 1 vote made room, so the queue still holds its bound.
        let released = queued.release(Slot(3));
        assert_eq!(released.len(), MAX_QUEUED_VOTES);
        assert_eq!(released.last(), Some(&vote(2)));
        assert_eq!(
            released.iter().filter(|held| **held == vote(1)).count(),
            MAX_QUEUED_VOTES - 1
        );
    }
}
