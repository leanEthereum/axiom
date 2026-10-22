//! Participation flags and inactivity scores, from Altair on.

use axiom_ssz::{CapacityError, Sequence, SequenceMut};

use crate::{ParticipationFlags, accessors::CoreState};

/// Per-validator participation flags of two epochs, and inactivity scores.
///
/// Altair replaced phase0's pending attestations with these lists.
/// See the Altair beacon chain spec.
///
/// # Invariants
///
/// Each list holds one entry per validator.
pub trait ParticipationState: CoreState {
    /// Duties each validator fulfilled in the previous epoch.
    fn previous_epoch_participation(&self) -> &Sequence<ParticipationFlags>;

    /// Duties each validator fulfilled in the current epoch.
    fn current_epoch_participation(&self) -> &Sequence<ParticipationFlags>;

    /// Flags of the previous and the current epoch, in that order, for edits in place.
    fn epoch_participation_mut(
        &mut self,
    ) -> (
        SequenceMut<'_, ParticipationFlags>,
        SequenceMut<'_, ParticipationFlags>,
    );

    /// Per-validator inactivity scores, which drive the inactivity leak.
    fn inactivity_scores(&self) -> &Sequence<u64>;

    /// Per-validator inactivity scores, for edits in place.
    fn inactivity_scores_mut(&mut self) -> SequenceMut<'_, u64>;

    /// Appends empty flags and a zero score for a validator just added to the registry.
    ///
    /// See `add_validator_to_registry` in the Altair beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when a list is at its limit.
    fn push_participant(&mut self) -> Result<(), CapacityError>;
}
