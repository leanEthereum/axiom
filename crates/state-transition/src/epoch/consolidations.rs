//! The consolidation queue, drained as sources become withdrawable.

use axiom_types::{Epoch, Preset};

use crate::{State, StateError};

/// One epoch's pass over the pending consolidations.
///
/// Only the active part moves: the lesser of balance and effective balance.
/// Anything above stays behind to be withdrawn.
///
/// See `process_pending_consolidations` in the Electra beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ConsolidationQueue {
    /// The epoch after the ending one.
    next_epoch: Epoch,
}

impl ConsolidationQueue {
    /// The pass at the end of an epoch.
    pub(super) fn new(current_epoch: Epoch) -> Self {
        Self {
            next_epoch: current_epoch + 1,
        }
    }

    /// Moves the stake of consolidated validators once they become withdrawable.
    ///
    /// # Errors
    ///
    /// Fails when a validator does not exist or a balance overflows.
    pub(super) fn apply<P: Preset>(self, state: &mut State<P>) -> Result<(), StateError> {
        let mut next_pending = 0;
        let queue = state.beacon.pending_consolidations.clone();

        for consolidation in &queue {
            let validators = &state.beacon.validators;
            let source = validators
                .get(consolidation.source_index.as_usize())
                .ok_or(StateError::UnknownValidator {
                    index: consolidation.source_index,
                    registry_size: validators.len(),
                })?;
            if source.slashed {
                next_pending += 1;
                continue;
            }
            if source.withdrawable_epoch > self.next_epoch {
                break;
            }
            let balance = state.beacon.balances[consolidation.source_index.as_usize()];
            let amount = balance.min(source.effective_balance);
            state.decrease_balance(consolidation.source_index, amount)?;
            state.increase_balance(consolidation.target_index, amount)?;
            next_pending += 1;
        }

        state.beacon.pending_consolidations.drain(..next_pending);
        Ok(())
    }
}
