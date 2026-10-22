//! Inactivity scores: the memory of missed targets that drives the inactivity leak.

use axiom_types::{
    ChainConfig, Epoch, accessors::ParticipationState, constants::TIMELY_TARGET_FLAG_INDEX,
};

use super::Participation;

/// The score changes of one epoch, decided from the previous epoch's target votes.
///
/// A missed target adds the bias, a hit removes one point.
/// Outside a leak every score also decays by the recovery rate.
///
/// See `process_inactivity_updates` in the Altair beacon chain spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InactivityUpdates {
    /// Each eligible validator, with whether it hit the previous epoch's target.
    votes: Vec<(usize, bool)>,
    /// Points a missed target adds.
    bias: u64,
    /// Points every score loses outside a leak.
    recovery: u64,
    /// Whether the chain is in an inactivity leak.
    in_leak: bool,
}

impl InactivityUpdates {
    /// The updates the ending epoch's participation calls for.
    ///
    /// Genesis has no previous epoch, so it changes no score.
    #[must_use]
    pub fn new<S: ParticipationState + ?Sized>(
        participation: &Participation<'_, S>,
        config: &ChainConfig,
    ) -> Self {
        let state = participation.state();
        let votes = if participation.current_epoch() == Epoch::GENESIS {
            Vec::new()
        } else {
            state
                .eligible_validator_indices()
                .into_iter()
                .map(|index| {
                    let index = index.as_usize();
                    (
                        index,
                        participation.is_previous_participant(index, TIMELY_TARGET_FLAG_INDEX),
                    )
                })
                .collect()
        };
        Self {
            votes,
            bias: config.inactivity_score_bias,
            recovery: config.inactivity_score_recovery_rate,
            in_leak: state.is_in_inactivity_leak(),
        }
    }

    /// Writes the new scores into the state.
    pub fn apply<S: ParticipationState + ?Sized>(self, state: &mut S) {
        let scores = state.inactivity_scores_mut();
        for (index, participated) in self.votes {
            let score = &mut scores[index];
            *score = if participated {
                score.saturating_sub(1)
            } else {
                score.saturating_add(self.bias)
            };
            if !self.in_leak {
                *score = score.saturating_sub(self.recovery);
            }
        }
    }
}
