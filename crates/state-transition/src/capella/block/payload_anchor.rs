//! What a payload claims about its place in the chain, checked unconditionally from Capella on.

use axiom_types::{Bytes32, ChainConfig, Hash32, accessors::CoreState};

use crate::{BlockError, StateError};

/// What a payload claims about its place in the chain: its parent, randomness, and time.
///
/// Bellatrix skipped the parent check for the first payload of the merge.
/// Capella dropped that case, so every later fork checks these three the same way.
/// See `process_execution_payload` in the Capella beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadAnchor {
    /// Block hash of the payload's parent.
    pub parent_hash: Hash32,
    /// Randomness the payload uses.
    pub prev_randao: Bytes32,
    /// The payload's timestamp, in seconds.
    pub timestamp: u64,
}

impl PayloadAnchor {
    /// Checks the payload extends the latest payload, at the state's randomness and slot time.
    ///
    /// # Errors
    ///
    /// Fails when the parent, randomness, or timestamp does not match.
    pub fn check<S: CoreState + ?Sized>(
        self,
        state: &S,
        latest_block_hash: Hash32,
        config: &ChainConfig,
    ) -> Result<(), BlockError> {
        if self.parent_hash != latest_block_hash {
            return Err(BlockError::PayloadParentMismatch {
                claimed: self.parent_hash,
                expected: latest_block_hash,
            });
        }
        let randao_mix = state.randao_mix(state.current_epoch());
        if self.prev_randao != randao_mix {
            return Err(BlockError::PayloadRandaoMismatch {
                claimed: self.prev_randao,
                expected: randao_mix,
            });
        }
        // Timing: genesis time plus the slot's whole milliseconds, truncated to seconds.
        let slot_ms =
            state
                .slot()
                .0
                .checked_mul(config.slot_duration_ms)
                .ok_or(StateError::Overflow {
                    quantity: "slot time in milliseconds",
                })?;
        let expected = state.genesis_time() + slot_ms / 1000;
        if self.timestamp != expected {
            return Err(BlockError::PayloadTimestampMismatch {
                claimed: self.timestamp,
                expected,
            });
        }
        Ok(())
    }
}
