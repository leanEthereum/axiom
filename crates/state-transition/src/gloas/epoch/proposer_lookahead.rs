//! The proposer lookahead, drawn among unslashed validators only.

use axiom_types::{
    Epoch, ValidatorIndex,
    accessors::{ForkState, LookaheadState},
};

use crate::{StateError, fulu, sampling::WeightedSampler};

/// The shift of the proposer lookahead at the end of an epoch, by Gloas's rule.
///
/// A slashed validator stays active until it exits, but can no longer propose.
/// Gloas removes it from the draw, so no slot of the lookahead goes to waste.
/// The shift itself is Fulu's.
///
/// See EIP-8045 and `get_beacon_proposer_indices` in the Gloas beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposerLookahead {
    /// The epoch that is ending.
    ending: Epoch,
}

impl ProposerLookahead {
    /// The shift out of an ending epoch.
    #[must_use]
    pub const fn new(ending: Epoch) -> Self {
        Self { ending }
    }

    /// Drops the ending epoch's proposers, and appends those of the epoch after the next.
    ///
    /// See `process_proposer_lookahead` in the Fulu beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the new epoch has no unslashed active validator.
    pub fn shift<S: LookaheadState + ForkState>(self, state: &mut S) -> Result<(), StateError> {
        let shift = fulu::epoch::ProposerLookahead::new(self.ending);
        let epoch = shift.appended_epoch::<S::Preset>();
        let validators = state.validators();
        let candidates: Vec<ValidatorIndex> = state
            .active_validator_indices(epoch)
            .into_iter()
            .filter(|index| !validators[index.as_usize()].slashed)
            .collect();
        if candidates.is_empty() {
            return Err(StateError::NoActiveValidators(epoch));
        }
        let proposers = WeightedSampler::proposers_among(&*state, epoch, &candidates)?;
        fulu::epoch::ProposerLookahead::advance(state, &proposers);
        Ok(())
    }
}
