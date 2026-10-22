//! The randao step: mixing the proposer's reveal into the chain's randomness.

use axiom_types::{BlsSignature, Bytes32, Preset, Root, constants::DOMAIN_RANDAO};

use crate::{BlockError, BlockProcessor, Fork, Operation};

/// The proposer's randao reveal: its signature over the current epoch.
///
/// The reveal is deterministic, so the proposer's only choice is to reveal or to skip the slot.
/// That caps a proposer's bias of the randomness at one bit per slot it controls.
#[derive(Clone, Copy, Debug)]
pub struct RandaoReveal(pub BlsSignature);

impl<S: Fork> Operation<S> for RandaoReveal {
    /// Checks the reveal and mixes its hash into the current mix.
    ///
    /// No fork changed this step.
    /// See `process_randao` in the phase0 beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let state = processor.state.beacon();
        let epoch = state.current_epoch();
        let domain = state.domain(DOMAIN_RANDAO, epoch);
        let proposer = processor.proposer()?;
        processor.verify_signature(proposer, &epoch, domain, &self.0)?;

        // mix = previous mix XOR sha256(reveal)
        let state = &mut *processor.state.beacon;
        let reveal_hash = Root::sha256(&self.0.0);
        let mut mix = state.randao_mix(epoch);
        for (byte, hashed) in mix.0.iter_mut().zip(reveal_hash.0) {
            *byte ^= hashed;
        }
        let slot = (epoch % S::Preset::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
        state.randao_mixes_mut()[slot] = Bytes32(mix.0);
        Ok(())
    }
}
