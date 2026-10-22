//! Rotations that look ahead: sync committees and the proposer lookahead.

use std::mem;

use axiom_types::{Preset, ValidatorIndex};

use super::EpochProcessor;
use crate::StateError;

impl<P: Preset> EpochProcessor<'_, P> {
    /// Rotates the sync committees when a period ends.
    ///
    /// The next committee is drawn a full period ahead.
    /// A light client can then learn it from the current committee's signatures.
    ///
    /// See `process_sync_committee_updates` in the Altair beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the next committee cannot be drawn.
    pub fn process_sync_committee_updates(&mut self) -> Result<(), StateError> {
        if (self.current_epoch + 1)
            .0
            .is_multiple_of(P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD)
        {
            let next = self.state.next_sync_committee()?;
            let state = &mut self.state.beacon;
            state.current_sync_committee = mem::replace(&mut state.next_sync_committee, next);
        }
        Ok(())
    }

    /// Drops the ending epoch's proposers, and appends those of the epoch after the next.
    ///
    /// ```text
    /// lookahead before: [ epoch e   | epoch e+1 ]
    /// lookahead after:  [ epoch e+1 | epoch e+2 ]
    /// ```
    ///
    /// Fixing proposers an epoch early lets them prepare, and keeps the schedule stable.
    /// See EIP-7917 and `process_proposer_lookahead` in the Fulu beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the new epoch has no active validator.
    pub fn process_proposer_lookahead(&mut self) -> Result<(), StateError> {
        let epoch = self.current_epoch + P::MIN_SEED_LOOKAHEAD + 1;
        let proposers: Vec<ValidatorIndex> = self.state.beacon_proposer_indices(epoch)?;
        let lookahead = &mut self.state.beacon.proposer_lookahead;
        let slots = P::SLOTS_PER_EPOCH as usize;
        lookahead.rotate_left(slots);
        let tail = lookahead.len() - slots;
        lookahead[tail..].copy_from_slice(&proposers);
        Ok(())
    }
}
