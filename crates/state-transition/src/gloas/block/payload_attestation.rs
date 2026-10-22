//! Payload attestations: the payload timeliness committee's vote on the parent's payload.

use axiom_bls::PublicKey;
use axiom_types::{
    ValidatorIndex, accessors::BuilderState, constants::DOMAIN_PTC_ATTESTER,
    gloas::PayloadAttestation, phase0::SigningData,
};

use crate::{BlockError, BlockProcessor, Fork, Operation, gloas::ptc::PtcWindow};

impl<S: Fork + BuilderState> Operation<S> for PayloadAttestation<S::Preset> {
    /// Checks an aggregate vote of the parent slot's payload timeliness committee.
    ///
    /// The vote must be on the parent block, from the previous slot, with a valid signature.
    /// Its content changes no state: fork choice reads it, block processing only checks it.
    ///
    /// A validator may hold several seats in the committee.
    /// Its key then counts once per seat in the aggregate, as each seat signed.
    ///
    /// See `process_payload_attestation` and `get_indexed_payload_attestation` in the Gloas spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let data = &self.data;
        let state = processor.state.beacon();
        let parent_root = state.latest_block_header().parent_root;
        if data.beacon_block_root != parent_root {
            return Err(BlockError::PayloadAttestationBlockMismatch {
                claimed: data.beacon_block_root,
                expected: parent_root,
            });
        }
        if data.slot.checked_add(1) != Some(state.slot()) {
            return Err(BlockError::PayloadAttestationSlotMismatch {
                slot: data.slot,
                state_slot: state.slot(),
            });
        }

        let committee = PtcWindow::of_slot(state, data.slot, processor.config.gloas_fork_epoch)?;
        let mut indices: Vec<ValidatorIndex> = committee
            .iter()
            .zip(self.aggregation_bits.iter())
            .filter(|(_, bit)| *bit)
            .map(|(index, _)| *index)
            .collect();
        indices.sort_unstable();
        if indices.is_empty() {
            return Err(BlockError::EmptyAttestingIndices);
        }

        // See `is_valid_indexed_payload_attestation` in the Gloas spec.
        if !processor.checks_signatures() {
            return Ok(());
        }
        let keys = indices
            .iter()
            .map(|index| processor.state.public_key(*index))
            .collect::<Result<Vec<_>, _>>()?;
        let key = PublicKey::aggregate(&keys).map_err(BlockError::InvalidAggregateKey)?;
        let domain = processor
            .state
            .beacon()
            .domain(DOMAIN_PTC_ATTESTER, data.slot.epoch::<S::Preset>());
        let root = SigningData::signing_root(data, domain);
        processor.verify_root(key, root, &self.signature)
    }
}
