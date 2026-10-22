//! The rotation of participation flags into the previous epoch.

use axiom_types::{ParticipationFlags, accessors::ParticipationState};

/// The end-of-epoch shift of participation flags.
///
/// The current epoch's flags become the previous epoch's, and the current ones restart empty.
/// The lists keep their length, one entry per validator, so the shift happens in place.
///
/// See `process_participation_flag_updates` in the Altair beacon chain spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlagRotation;

impl FlagRotation {
    /// Shifts the flags of a state.
    pub fn apply<S: ParticipationState + ?Sized>(self, state: &mut S) {
        let (previous, current) = state.epoch_participation_mut();
        previous.copy_from_slice(current);
        current.fill(ParticipationFlags::default());
    }
}
