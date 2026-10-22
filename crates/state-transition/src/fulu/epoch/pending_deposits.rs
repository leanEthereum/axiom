//! The deposit queue, once the contract deposits are retired.

use axiom_types::accessors::ParticipationState;

use crate::{Registry, StateError, electra, electra::churn::BalanceChurn};

/// One epoch's pass over the pending deposits, by Fulu's rule.
///
/// Electra held deposit requests back until the contract deposits before them were bridged.
/// Fulu retired the contract deposits, so it drops that wait and keeps the rest of the pass.
/// See `process_pending_deposits` in the Fulu beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositQueue(electra::epoch::DepositQueue);

impl DepositQueue {
    /// The pass due at a state, under its registry's churn.
    #[must_use]
    pub fn new<S: BalanceChurn>(registry: &Registry<'_, S>) -> Self {
        Self(electra::epoch::DepositQueue::new(registry).without_bridge())
    }

    /// Applies queued deposits in order, until the churn or the per-epoch cap runs out.
    ///
    /// # Errors
    ///
    /// Fails when a list is full or a balance overflows.
    pub fn apply<S: BalanceChurn + ParticipationState>(
        self,
        registry: &mut Registry<'_, S>,
    ) -> Result<(), StateError> {
        self.0.apply(registry)
    }
}
