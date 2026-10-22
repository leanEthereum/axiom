//! The randao step: mixing the proposer's reveal into the chain's randomness.

use axiom_types::{BlsSignature, Bytes32, Preset, Root, constants::DOMAIN_RANDAO};

use super::{BlockProcessor, Operation};
use crate::BlockError;

/// The proposer's randao reveal: its signature over the current epoch.
///
/// The reveal is deterministic, so the proposer's only choice is to reveal or to skip the slot.
/// That caps a proposer's bias of the randomness at one bit per slot it controls.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RandaoReveal(pub(crate) BlsSignature);

impl<P: Preset> Operation<P> for RandaoReveal {
    /// Checks the reveal and mixes its hash into the current mix.
    ///
    /// See `process_randao` in the phase0 beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError> {
        let state = &processor.state.beacon;
        let epoch = state.current_epoch();
        let proposer = state.beacon_proposer_index();
        let domain = state.domain(DOMAIN_RANDAO, epoch);
        processor.verify_signature(proposer, &epoch, domain, &self.0)?;

        // mix = previous mix XOR sha256(reveal)
        let state = &mut processor.state.beacon;
        let reveal_hash = Root::sha256(&self.0.0);
        let mut mix = state.randao_mix(epoch);
        for (byte, hashed) in mix.0.iter_mut().zip(reveal_hash.0) {
            *byte ^= hashed;
        }
        state.randao_mixes[(epoch % P::EPOCHS_PER_HISTORICAL_VECTOR) as usize] = Bytes32(mix.0);
        Ok(())
    }
}
