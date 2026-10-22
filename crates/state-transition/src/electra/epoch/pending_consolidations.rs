//! The consolidation queue, drained as sources become withdrawable.

use axiom_types::{Epoch, accessors::PendingQueueState};

use crate::{CachedState, StateError};

/// One epoch's pass over the pending consolidations.
///
/// Only the active part moves: the lesser of balance and effective balance.
/// Anything above stays behind to be withdrawn.
///
/// See `process_pending_consolidations` in the Electra beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsolidationQueue {
    /// The epoch after the ending one.
    next_epoch: Epoch,
}

impl ConsolidationQueue {
    /// The pass at the end of an epoch.
    #[must_use]
    pub fn new(current_epoch: Epoch) -> Self {
        Self {
            next_epoch: current_epoch + 1,
        }
    }

    /// Moves the stake of consolidated validators once they become withdrawable.
    ///
    /// # Errors
    ///
    /// Fails when a validator does not exist or a balance overflows.
    pub fn apply<S: PendingQueueState>(
        self,
        state: &mut CachedState<'_, S>,
    ) -> Result<(), StateError> {
        let mut next_pending = 0;
        let queue = state.beacon().pending_consolidations().to_vec();
        for consolidation in &queue {
            let validators = state.beacon().validators();
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
            let balance = state.beacon().balances()[consolidation.source_index.as_usize()];
            let amount = balance.min(source.effective_balance);
            state.decrease_balance(consolidation.source_index, amount)?;
            state.increase_balance(consolidation.target_index, amount)?;
            next_pending += 1;
        }
        state.beacon.remove_pending_consolidations(next_pending);
        Ok(())
    }
}
