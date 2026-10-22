//! Attestations includable until the end of the epoch after their own.

use axiom_types::{Preset, accessors::ParticipationState, phase0::Attestation};

use crate::{BlockError, BlockProcessor, Fork, Operation, altair::block::FlaggedAttestation};

/// A single-committee attestation, with no inclusion window beyond its target epoch.
///
/// Altair accepted a vote at most one epoch after its slot.
/// Deneb accepts it while its target is the previous or current epoch, see EIP-7045.
/// The target flag no longer expires either, so late votes still count for finality.
#[derive(Clone, Copy, Debug)]
pub struct UnboundedAttestation<'a, P: Preset>(pub &'a Attestation<P>);

impl<S: Fork + ParticipationState> Operation<S> for UnboundedAttestation<'_, S::Preset> {
    /// Records an aggregate's votes, with Altair's rule and no inclusion window.
    ///
    /// See `process_attestation` in the Deneb beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        FlaggedAttestation(self.0).apply_within(processor, None)
    }
}
