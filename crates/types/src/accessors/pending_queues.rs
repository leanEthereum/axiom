//! Electra's pending queues and balance churn, from Electra on.

use axiom_ssz::{CapacityError, Sequence};

use crate::{
    Epoch, Gwei, ValidatorIndex,
    accessors::CoreState,
    electra::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal},
};

/// Queues of stake waiting for churn, and the tails of the exit and consolidation queues.
///
/// See EIP-6110, EIP-7002, EIP-7251, and the Electra beacon chain spec.
pub trait PendingQueueState: CoreState {
    /// Deposit contract index of the first deposit request, see EIP-6110.
    fn deposit_requests_start_index(&self) -> u64;

    /// Index of the first deposit request, for deposit request processing.
    fn deposit_requests_start_index_mut(&mut self) -> &mut u64;

    /// Deposit churn carried over from the previous epoch.
    fn deposit_balance_to_consume(&self) -> Gwei;

    /// Deposit churn carried over, for the deposit queue.
    fn deposit_balance_to_consume_mut(&mut self) -> &mut Gwei;

    /// Exit churn left in the latest exit epoch.
    fn exit_balance_to_consume(&self) -> Gwei;

    /// Exit churn left, for the exit queue.
    fn exit_balance_to_consume_mut(&mut self) -> &mut Gwei;

    /// Earliest epoch a new exit can be scheduled for.
    fn earliest_exit_epoch(&self) -> Epoch;

    /// Earliest exit epoch, for the exit queue.
    fn earliest_exit_epoch_mut(&mut self) -> &mut Epoch;

    /// Consolidation churn left in the latest consolidation epoch.
    fn consolidation_balance_to_consume(&self) -> Gwei;

    /// Consolidation churn left, for the consolidation queue.
    fn consolidation_balance_to_consume_mut(&mut self) -> &mut Gwei;

    /// Earliest epoch a new consolidation can be scheduled for.
    fn earliest_consolidation_epoch(&self) -> Epoch;

    /// Earliest consolidation epoch, for the consolidation queue.
    fn earliest_consolidation_epoch_mut(&mut self) -> &mut Epoch;

    /// Deposits waiting for churn, oldest first.
    fn pending_deposits(&self) -> &Sequence<PendingDeposit>;

    /// Queues a deposit at the back.
    ///
    /// # Errors
    ///
    /// Fails when the queue is at its limit.
    fn push_pending_deposit(&mut self, deposit: PendingDeposit) -> Result<(), CapacityError>;

    /// Drops the oldest deposits, which processing consumed.
    fn remove_pending_deposits(&mut self, count: usize);

    /// Partial withdrawals waiting for their epoch, oldest first.
    fn pending_partial_withdrawals(&self) -> &Sequence<PendingPartialWithdrawal>;

    /// Queues a partial withdrawal at the back.
    ///
    /// # Errors
    ///
    /// Fails when the queue is at its limit.
    fn push_pending_partial_withdrawal(
        &mut self,
        withdrawal: PendingPartialWithdrawal,
    ) -> Result<(), CapacityError>;

    /// Drops the oldest partial withdrawals, which a payload served.
    fn remove_pending_partial_withdrawals(&mut self, count: usize);

    /// Consolidations waiting for their source to be withdrawable, oldest first.
    fn pending_consolidations(&self) -> &Sequence<PendingConsolidation>;

    /// Queues a consolidation at the back.
    ///
    /// # Errors
    ///
    /// Fails when the queue is at its limit.
    fn push_pending_consolidation(
        &mut self,
        consolidation: PendingConsolidation,
    ) -> Result<(), CapacityError>;

    /// Drops the oldest consolidations, which processing consumed.
    fn remove_pending_consolidations(&mut self, count: usize);

    /// Balance already queued for partial withdrawal from a validator.
    ///
    /// See `get_pending_balance_to_withdraw` in the Electra beacon chain spec.
    fn pending_balance_to_withdraw(&self, index: ValidatorIndex) -> Gwei {
        self.pending_partial_withdrawals()
            .iter()
            .filter(|withdrawal| withdrawal.validator_index == index)
            .map(|withdrawal| withdrawal.amount)
            .sum()
    }
}
