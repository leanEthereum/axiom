//! Validators' latest votes and the equivocators whose votes no longer count.

use std::collections::{HashMap, HashSet};

use axiom_types::{Epoch, Root, ValidatorIndex};

/// A validator's most recent head vote.
///
/// See `LatestMessage` in the phase0 fork choice spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatestMessage {
    /// Target epoch of the vote, which orders votes from one validator.
    pub epoch: Epoch,
    /// The head block voted for.
    pub root: Root,
}

/// Every validator's latest vote, and the set of proven equivocators.
///
/// LMD-GHOST counts one vote per validator: the one with the latest target epoch.
/// An equivocator loses its vote for good, so it cannot split weight between forks.
#[derive(Clone, Debug, Default)]
pub struct Votes {
    /// Latest vote per validator.
    latest: HashMap<ValidatorIndex, LatestMessage>,
    /// Validators caught casting slashable votes.
    equivocating: HashSet<ValidatorIndex>,
}

impl Votes {
    /// Records votes for a block, keeping only votes newer than each validator's latest.
    ///
    /// See `update_latest_messages` in the phase0 fork choice spec.
    pub fn record(
        &mut self,
        voters: impl IntoIterator<Item = ValidatorIndex>,
        message: LatestMessage,
    ) {
        for voter in voters {
            if self.equivocating.contains(&voter) {
                continue;
            }
            let newer = self
                .latest
                .get(&voter)
                .is_none_or(|current| message.epoch > current.epoch);
            if newer {
                self.latest.insert(voter, message);
            }
        }
    }

    /// Marks validators as equivocators, removing their weight from every block.
    pub fn mark_equivocating(&mut self, validators: impl IntoIterator<Item = ValidatorIndex>) {
        self.equivocating.extend(validators);
    }

    /// Whether a validator is a known equivocator.
    #[must_use]
    pub fn is_equivocating(&self, validator: ValidatorIndex) -> bool {
        self.equivocating.contains(&validator)
    }

    /// The vote that counts for a validator: its latest, unless it equivocated.
    #[must_use]
    pub fn counted(&self, validator: ValidatorIndex) -> Option<&LatestMessage> {
        if self.is_equivocating(validator) {
            return None;
        }
        self.latest.get(&validator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(epoch: u64, tag: u8) -> LatestMessage {
        LatestMessage {
            epoch: Epoch(epoch),
            root: Root([tag; 32]),
        }
    }

    #[test]
    fn only_a_later_target_replaces_a_vote() {
        let mut votes = Votes::default();
        votes.record([ValidatorIndex(1)], message(2, 0xa));

        // Same epoch: the first vote stands.
        votes.record([ValidatorIndex(1)], message(2, 0xb));
        assert_eq!(votes.counted(ValidatorIndex(1)), Some(&message(2, 0xa)));

        // Later epoch: the vote moves.
        votes.record([ValidatorIndex(1)], message(3, 0xb));
        assert_eq!(votes.counted(ValidatorIndex(1)), Some(&message(3, 0xb)));
    }

    #[test]
    fn equivocators_lose_their_vote() {
        let mut votes = Votes::default();
        votes.record([ValidatorIndex(7)], message(1, 0xa));
        votes.mark_equivocating([ValidatorIndex(7)]);

        assert_eq!(votes.counted(ValidatorIndex(7)), None);

        // A later vote from an equivocator is ignored.
        votes.record([ValidatorIndex(7)], message(5, 0xb));
        assert_eq!(votes.counted(ValidatorIndex(7)), None);
    }
}
