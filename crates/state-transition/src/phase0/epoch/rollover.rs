//! End-of-epoch resets of the ring buffers and per-period fields phase0 defined.

use std::mem;

use axiom_ssz::PersistentList;
use axiom_types::{Epoch, Gwei, Preset, accessors::CoreState, phase0::BeaconState};

/// The passage from the ending epoch to the next one.
///
/// Ring buffers indexed by epoch advance one slot, and per-period fields restart.
/// No fork changed these steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rollover {
    /// The epoch that is ending.
    current: Epoch,
    /// The epoch that begins.
    next: Epoch,
}

impl Rollover {
    /// The passage out of an epoch.
    #[must_use]
    pub fn new(current: Epoch) -> Self {
        Self {
            current,
            next: current + 1,
        }
    }

    /// Clears the eth1 data votes when a voting period ends.
    ///
    /// See `process_eth1_data_reset` in the phase0 beacon chain spec.
    pub fn reset_eth1_data<S: CoreState + ?Sized>(self, state: &mut S) {
        if self
            .next
            .0
            .is_multiple_of(S::Preset::EPOCHS_PER_ETH1_VOTING_PERIOD)
        {
            *state.eth1_data_votes_mut() = PersistentList::new();
        }
    }

    /// Clears the slashings slot the next epoch will accumulate into.
    ///
    /// See `process_slashings_reset` in the phase0 beacon chain spec.
    pub fn reset_slashings<S: CoreState + ?Sized>(self, state: &mut S) {
        let next = self.next % S::Preset::EPOCHS_PER_SLASHINGS_VECTOR;
        state.slashings_mut()[next as usize] = Gwei::ZERO;
    }

    /// Seeds the next epoch's randao mix with the current one.
    ///
    /// See `process_randao_mixes_reset` in the phase0 beacon chain spec.
    pub fn reset_randao_mix<S: CoreState + ?Sized>(self, state: &mut S) {
        let next = self.next % S::Preset::EPOCHS_PER_HISTORICAL_VECTOR;
        let mix = state.randao_mix(self.current);
        state.randao_mixes_mut()[next as usize] = mix;
    }

    /// Moves the current epoch's pending attestations to the previous epoch's list.
    ///
    /// See `process_participation_record_updates` in the phase0 beacon chain spec.
    pub fn rotate_pending_attestations<P: Preset>(self, state: &mut BeaconState<P>) {
        state.previous_epoch_attestations = mem::take(&mut state.current_epoch_attestations);
    }
}
