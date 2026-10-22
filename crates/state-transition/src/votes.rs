//! Which parts of each validator's vote of the previous epoch a state records as right.

use axiom_types::{
    Epoch, ValidatorIndex,
    accessors::{CoreState, ParticipationState},
    constants::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
};

use crate::phase0::epoch::{PendingParticipation, VotePart};

/// What the chain recorded of one validator's duty to vote in an epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VoteRecord {
    /// The validator owed no vote: it was not active, or it was slashed.
    #[default]
    Exempt,
    /// The validator owed a vote, and this is what the chain recorded of it.
    Owed(RecordedVote),
}

/// The parts of an owed vote the chain recorded as right.
///
/// Before Altair, any included vote has its source right, and the inclusion delay is known.
/// From Altair on, a part counts only when it was timely, and the delay is not kept.
/// See the epoch processing helpers of the phase0 and Altair beacon chain specs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordedVote {
    /// Whether the vote's source was right.
    pub source: bool,
    /// Whether the vote's target was right.
    pub target: bool,
    /// Whether the vote's head was right.
    pub head: bool,
    /// Slots between the vote and its earliest inclusion, before Altair.
    pub inclusion_delay: Option<u64>,
}

/// The vote records of every validator for one epoch.
///
/// A state at the end of epoch e + 1 holds the final records of epoch e.
/// No block of a later epoch may include a vote of epoch e.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EpochVotes {
    /// The epoch the votes are for.
    pub epoch: Epoch,
    /// One record per validator, by index.
    records: Vec<VoteRecord>,
}

impl EpochVotes {
    /// The record of a validator, when it is in the registry.
    #[must_use]
    pub fn of(&self, validator: ValidatorIndex) -> Option<VoteRecord> {
        self.records.get(validator.as_usize()).copied()
    }

    /// The records a phase0 state's pending attestations show, for its previous epoch.
    ///
    /// See `get_matching_source_attestations` and its siblings in the phase0 beacon chain spec.
    #[must_use]
    pub fn of_pending(state: &impl CoreState, participation: &PendingParticipation) -> Self {
        let epoch = state.previous_epoch();
        let records = state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                if !validator.is_active_at(epoch) || validator.slashed {
                    return VoteRecord::Exempt;
                }
                VoteRecord::Owed(RecordedVote {
                    source: participation.has_previous(index, VotePart::Source),
                    target: participation.has_previous(index, VotePart::Target),
                    head: participation.has_previous(index, VotePart::Head),
                    inclusion_delay: participation
                        .earliest_inclusion(index)
                        .map(|inclusion| inclusion.delay),
                })
            })
            .collect();
        Self { epoch, records }
    }

    /// The records a state's participation flags show, for its previous epoch, from Altair on.
    ///
    /// Slashed validators count as absent, as the spec's unslashed participating indices say.
    /// See `get_unslashed_participating_indices` in the Altair beacon chain spec.
    #[must_use]
    pub fn of_participation(state: &impl ParticipationState) -> Self {
        let epoch = state.previous_epoch();
        let flags = state.previous_epoch_participation();
        let records = state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                if !validator.is_active_at(epoch) || validator.slashed {
                    return VoteRecord::Exempt;
                }
                let flags = flags[index];
                VoteRecord::Owed(RecordedVote {
                    source: flags.has(TIMELY_SOURCE_FLAG_INDEX),
                    target: flags.has(TIMELY_TARGET_FLAG_INDEX),
                    head: flags.has(TIMELY_HEAD_FLAG_INDEX),
                    inclusion_delay: None,
                })
            })
            .collect();
        Self { epoch, records }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Gwei, Minimal, ParticipationFlags, Slot, altair, phase0::Validator};

    use super::*;

    /// An active validator of one full deposit, slashed or not.
    fn validator(slashed: bool) -> Validator {
        Validator {
            effective_balance: Gwei(32_000_000_000),
            activation_epoch: Epoch(0),
            exit_epoch: Epoch::FAR_FUTURE,
            withdrawable_epoch: Epoch::FAR_FUTURE,
            slashed,
            ..Validator::default()
        }
    }

    #[test]
    fn participation_flags_read_as_timely_parts() {
        // Fixture state: slot 20, in epoch 2, so the previous epoch is 1.
        //
        //     validator 0: source, target, head      validator 1: source only
        //     validator 2: every flag, but slashed
        let mut state = altair::BeaconState::<Minimal> {
            slot: Slot(20),
            ..altair::BeaconState::default()
        };
        let every = ParticipationFlags(0b111);
        for (slashed, flags) in [
            (false, every),
            (false, ParticipationFlags(0b001)),
            (true, every),
        ] {
            state.validators.push(validator(slashed)).unwrap();
            state.previous_epoch_participation.push(flags).unwrap();
        }

        let votes = EpochVotes::of_participation(&state);

        assert_eq!(votes.epoch, Epoch(1));
        let owed = |source, target, head| {
            VoteRecord::Owed(RecordedVote {
                source,
                target,
                head,
                inclusion_delay: None,
            })
        };
        assert_eq!(votes.of(ValidatorIndex(0)), Some(owed(true, true, true)));
        assert_eq!(votes.of(ValidatorIndex(1)), Some(owed(true, false, false)));
        assert_eq!(votes.of(ValidatorIndex(2)), Some(VoteRecord::Exempt));
        assert_eq!(votes.of(ValidatorIndex(3)), None);
    }
}
