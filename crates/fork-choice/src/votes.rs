//! Validators' latest votes and the equivocators whose votes no longer count.

use std::collections::{HashMap, HashSet};

use axiom_types::{Epoch, Preset, Root, Slot, ValidatorIndex};

/// A validator's most recent head vote.
///
/// Gloas tracks the slot of the vote and whether the voter saw the payload.
/// Earlier forks only order votes by epoch, which the slot also gives.
/// See `LatestMessage` in the phase0 and Gloas fork choice specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatestMessage {
    /// Slot of the vote.
    pub slot: Slot,
    /// The head block voted for.
    pub root: Root,
    /// Whether the voter saw the payload of the head block, from Gloas on.
    pub payload_present: bool,
}

impl LatestMessage {
    /// Epoch of the vote, which is also its target epoch.
    ///
    /// See `get_latest_message_epoch` in the phase0 and Gloas fork choice specs.
    #[must_use]
    pub const fn epoch<P: Preset>(&self) -> Epoch {
        self.slot.epoch::<P>()
    }
}

/// How a later vote from one validator supersedes its earlier one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteOrder {
    /// Only a vote with a later target epoch replaces the latest one.
    ///
    /// See `update_latest_messages` in the phase0 fork choice spec.
    ByEpoch,
    /// Any vote from a later slot replaces the latest one.
    ///
    /// See `update_latest_messages` in the Gloas fork choice spec.
    BySlot,
}

/// Every validator's latest vote, and the set of proven equivocators.
///
/// LMD-GHOST counts one vote per validator: its latest.
/// An equivocator loses its vote for good, so it cannot split weight between forks.
#[derive(Clone, Debug, Default)]
pub struct Votes {
    /// Latest vote per validator.
    latest: HashMap<ValidatorIndex, LatestMessage>,
    /// Validators caught casting slashable votes.
    equivocating: HashSet<ValidatorIndex>,
}

impl Votes {
    /// Records votes for a block, keeping only votes that supersede each validator's latest.
    ///
    /// See `update_latest_messages` in the phase0 and Gloas fork choice specs.
    pub fn record<P: Preset>(
        &mut self,
        voters: impl IntoIterator<Item = ValidatorIndex>,
        message: LatestMessage,
        order: VoteOrder,
    ) {
        for voter in voters {
            if self.equivocating.contains(&voter) {
                continue;
            }
            let newer = self.latest.get(&voter).is_none_or(|current| match order {
                VoteOrder::ByEpoch => message.epoch::<P>() > current.epoch::<P>(),
                VoteOrder::BySlot => message.slot > current.slot,
            });
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
    use axiom_types::Minimal;

    use super::*;

    fn message(slot: u64, tag: u8) -> LatestMessage {
        LatestMessage {
            slot: Slot(slot),
            root: Root([tag; 32]),
            payload_present: false,
        }
    }

    #[test]
    fn by_epoch_only_a_later_target_replaces_a_vote() {
        // Minimal epochs hold 8 slots: slots 16 and 17 share epoch 2.
        let mut votes = Votes::default();
        votes.record::<Minimal>([ValidatorIndex(1)], message(16, 0xa), VoteOrder::ByEpoch);

        // Same epoch: the first vote stands.
        votes.record::<Minimal>([ValidatorIndex(1)], message(17, 0xb), VoteOrder::ByEpoch);
        assert_eq!(votes.counted(ValidatorIndex(1)), Some(&message(16, 0xa)));

        // Slot 24 is epoch 3, later: the vote moves.
        votes.record::<Minimal>([ValidatorIndex(1)], message(24, 0xb), VoteOrder::ByEpoch);
        assert_eq!(votes.counted(ValidatorIndex(1)), Some(&message(24, 0xb)));
    }

    #[test]
    fn by_slot_a_later_slot_of_the_same_epoch_replaces_a_vote() {
        // Slots 16 and 17 share epoch 2, yet Gloas orders by slot.
        let mut votes = Votes::default();
        votes.record::<Minimal>([ValidatorIndex(1)], message(16, 0xa), VoteOrder::BySlot);
        votes.record::<Minimal>([ValidatorIndex(1)], message(17, 0xb), VoteOrder::BySlot);
        assert_eq!(votes.counted(ValidatorIndex(1)), Some(&message(17, 0xb)));

        // An equal slot does not replace it.
        votes.record::<Minimal>([ValidatorIndex(1)], message(17, 0xc), VoteOrder::BySlot);
        assert_eq!(votes.counted(ValidatorIndex(1)), Some(&message(17, 0xb)));
    }

    #[test]
    fn equivocators_lose_their_vote() {
        let mut votes = Votes::default();
        votes.record::<Minimal>([ValidatorIndex(7)], message(8, 0xa), VoteOrder::ByEpoch);
        votes.mark_equivocating([ValidatorIndex(7)]);

        assert_eq!(votes.counted(ValidatorIndex(7)), None);

        // A later vote from an equivocator is ignored.
        votes.record::<Minimal>([ValidatorIndex(7)], message(40, 0xb), VoteOrder::ByEpoch);
        assert_eq!(votes.counted(ValidatorIndex(7)), None);
    }
}
