//! Validators' latest votes and the equivocators whose votes no longer count.

use std::{
    collections::{HashMap, HashSet},
    mem,
};

use axiom_types::{Epoch, Preset, Root, Slot, ValidatorIndex};

use crate::{NodePayload, PayloadArrival};

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

    /// The node of its head block the vote supports, given the block's slot and payload.
    ///
    /// A vote from the block's own slot cannot have seen the payload, so it supports the block.
    /// A later vote supports the variant whose payload it claims to have seen.
    /// A block from before Gloas has only its full variant, whatever the vote says.
    /// See `get_supported_node` in the Gloas fork choice spec.
    #[must_use]
    pub const fn supported_payload(
        &self,
        block_slot: Slot,
        payload: PayloadArrival,
    ) -> NodePayload {
        match payload {
            PayloadArrival::Embedded => NodePayload::Full,
            PayloadArrival::Awaited | PayloadArrival::Revealed if block_slot.0 >= self.slot.0 => {
                NodePayload::Pending
            }
            PayloadArrival::Awaited | PayloadArrival::Revealed if self.payload_present => {
                NodePayload::Full
            }
            PayloadArrival::Awaited | PayloadArrival::Revealed => NodePayload::Empty,
        }
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
///
/// The validators whose counted vote changed are kept until the fork choice weighs them.
#[derive(Clone, Debug, Default)]
pub struct Votes {
    /// Latest vote per validator.
    latest: HashMap<ValidatorIndex, LatestMessage>,
    /// Validators caught casting slashable votes.
    equivocating: HashSet<ValidatorIndex>,
    /// Validators whose counted vote changed since the weights last took them in.
    changed: ChangedVoters,
}

/// The validators whose counted vote changed since the weights last took them in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ChangedVoters {
    /// These validators, possibly repeated.
    Listed(Vec<ValidatorIndex>),
    /// Every validator, as when the list outgrew the voters it could name.
    All,
}

impl Default for ChangedVoters {
    fn default() -> Self {
        Self::Listed(Vec::new())
    }
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
                self.note_change(voter);
            }
        }
    }

    /// Marks validators as equivocators, removing their weight from every block.
    pub fn mark_equivocating(&mut self, validators: impl IntoIterator<Item = ValidatorIndex>) {
        for validator in validators {
            if self.equivocating.insert(validator) {
                self.note_change(validator);
            }
        }
    }

    /// Whether a validator is a known equivocator.
    #[must_use]
    pub fn is_equivocating(&self, validator: ValidatorIndex) -> bool {
        // Why: equivocations are rare, and an empty set answers without hashing.
        !self.equivocating.is_empty() && self.equivocating.contains(&validator)
    }

    /// The vote that counts for a validator: its latest, unless it equivocated.
    #[must_use]
    pub fn counted(&self, validator: ValidatorIndex) -> Option<&LatestMessage> {
        if self.is_equivocating(validator) {
            return None;
        }
        self.latest.get(&validator)
    }

    /// Every validator that ever voted, equivocators included.
    pub(crate) fn voters(&self) -> impl Iterator<Item = ValidatorIndex> {
        self.latest.keys().copied()
    }

    /// Takes the validators whose counted vote changed since the last call.
    pub(crate) fn take_changed(&mut self) -> ChangedVoters {
        mem::take(&mut self.changed)
    }

    /// Notes that a validator's counted vote changed.
    ///
    /// A store that never weighs its votes would grow the list forever.
    /// Past one entry per known validator, the list collapses to naming every validator.
    fn note_change(&mut self, validator: ValidatorIndex) {
        if let ChangedVoters::Listed(changed) = &mut self.changed {
            if changed.len() > self.latest.len() + self.equivocating.len() {
                self.changed = ChangedVoters::All;
            } else {
                changed.push(validator);
            }
        }
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
    fn only_votes_that_change_the_count_are_reported() {
        // Fixture state: validator 1 votes in epoch 2, then again in the same epoch.
        let mut votes = Votes::default();
        votes.record::<Minimal>([ValidatorIndex(1)], message(16, 0xa), VoteOrder::ByEpoch);
        votes.record::<Minimal>([ValidatorIndex(1)], message(17, 0xb), VoteOrder::ByEpoch);
        // Only the first vote counted, so validator 1 is reported once.
        assert_eq!(
            votes.take_changed(),
            ChangedVoters::Listed(vec![ValidatorIndex(1)])
        );

        // Validator 1 equivocates once, then again: only the first proof changes its count.
        votes.mark_equivocating([ValidatorIndex(1)]);
        votes.mark_equivocating([ValidatorIndex(1)]);
        assert_eq!(
            votes.take_changed(),
            ChangedVoters::Listed(vec![ValidatorIndex(1)])
        );
        assert_eq!(votes.take_changed(), ChangedVoters::Listed(Vec::new()));
    }

    #[test]
    fn an_unread_list_collapses_to_every_validator() {
        // Fixture state: validator 1 votes in epochs 1, 2, and 3, nobody reading the changes.
        let mut votes = Votes::default();
        for slot in [8, 16, 24] {
            votes.record::<Minimal>([ValidatorIndex(1)], message(slot, 0xa), VoteOrder::ByEpoch);
        }
        // Two entries already cover the one voter, so the third change collapses the list.
        assert_eq!(votes.take_changed(), ChangedVoters::All);
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
