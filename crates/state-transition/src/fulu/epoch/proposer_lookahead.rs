//! The proposer lookahead, which fixes proposers one epoch ahead.

use axiom_types::{
    Epoch, Preset, ValidatorIndex,
    accessors::{ForkState, LookaheadState},
};

use crate::{StateError, sampling::WeightedSampler};

/// The shift of the proposer lookahead at the end of an epoch.
///
/// Fixing proposers an epoch early lets them prepare, and keeps the schedule stable.
/// See EIP-7917 and the Fulu beacon chain spec.
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

    /// Fills the whole lookahead from the state's current epoch, for a state that just became Fulu.
    ///
    /// The lookahead spans the current epoch and the next MIN_SEED_LOOKAHEAD epochs.
    /// See `initialize_proposer_lookahead` in the Fulu fork spec.
    ///
    /// # Errors
    ///
    /// Fails when an epoch of the lookahead has no active validator.
    pub fn initialize<S: LookaheadState + ForkState>(state: &mut S) -> Result<(), StateError> {
        let first = state.current_epoch();
        let mut proposers: Vec<ValidatorIndex> =
            Vec::with_capacity(state.proposer_lookahead().len());
        for offset in 0..=S::Preset::MIN_SEED_LOOKAHEAD {
            proposers.extend(WeightedSampler::proposers(&*state, first + offset)?);
        }
        state.proposer_lookahead_mut().copy_from_slice(&proposers);
        Ok(())
    }

    /// Drops the ending epoch's proposers, and appends those of the epoch after the next.
    ///
    /// ```text
    /// lookahead before: [ epoch e   | epoch e+1 ]
    /// lookahead after:  [ epoch e+1 | epoch e+2 ]
    /// ```
    ///
    /// See `process_proposer_lookahead` in the Fulu beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the new epoch has no active validator.
    pub fn shift<S: LookaheadState + ForkState>(self, state: &mut S) -> Result<(), StateError> {
        let proposers = WeightedSampler::proposers(&*state, self.appended_epoch::<S::Preset>())?;
        Self::advance(state, &proposers);
        Ok(())
    }

    /// The epoch whose proposers the shift appends.
    #[must_use]
    pub fn appended_epoch<P: Preset>(self) -> Epoch {
        self.ending + P::MIN_SEED_LOOKAHEAD + 1
    }

    /// Drops the oldest epoch of proposers, and appends one epoch drawn elsewhere.
    ///
    /// Gloas draws the appended epoch from a smaller pool, then shifts the same way.
    ///
    /// # Panics
    ///
    /// Panics when the proposers do not fill exactly one epoch.
    pub fn advance<S: LookaheadState>(state: &mut S, proposers: &[ValidatorIndex]) {
        let lookahead = state.proposer_lookahead_mut();
        let slots = S::Preset::SLOTS_PER_EPOCH as usize;
        lookahead.rotate_left(slots);
        let tail = lookahead.len() - slots;
        lookahead[tail..].copy_from_slice(proposers);
    }
}
