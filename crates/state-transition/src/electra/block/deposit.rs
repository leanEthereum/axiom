//! Deposits from the contract, bridged into the deposit queue until requests take over.

use axiom_types::{
    Gwei, Preset, Slot,
    accessors::{ParticipationState, PendingQueueState},
    electra::PendingDeposit,
    phase0::Deposit,
};

use crate::{
    BlockError, BlockProcessor, Fork, Operation, StateError, Verification,
    electra::deposits::DepositApplication, phase0::block::DepositInclusion,
};

/// A block's whole list of contract deposits, checked for completeness by Electra's rule.
///
/// Deposit requests replace the contract's deposits from the first request's index on.
/// The block must carry every contract deposit before that index it has room for.
#[derive(Clone, Copy, Debug)]
pub struct BridgeDeposits<'a>(pub &'a [Deposit]);

impl BridgeDeposits<'_> {
    /// Deposits a block at this state must carry.
    ///
    /// ```text
    /// limit    = min(eth1_data.deposit_count, deposit_requests_start_index)
    /// expected = min(MAX_DEPOSITS, limit - eth1_deposit_index), or 0 past the limit
    /// ```
    ///
    /// See `process_operations` in the Electra beacon chain spec.
    #[must_use]
    pub fn expected_count<S: PendingQueueState + ?Sized>(state: &S) -> u64 {
        let limit = state
            .eth1_data()
            .deposit_count
            .min(state.deposit_requests_start_index());
        limit
            .saturating_sub(state.eth1_deposit_index())
            .min(S::Preset::MAX_DEPOSITS)
    }
}

impl<S: Fork + ParticipationState + PendingQueueState> Operation<S> for BridgeDeposits<'_> {
    /// Checks the block carries exactly the deposits due, then applies each in order.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let expected = BridgeDeposits::expected_count(processor.state.beacon());
        if self.0.len() as u64 != expected {
            return Err(BlockError::DepositCountMismatch {
                expected,
                actual: self.0.len(),
            });
        }
        self.0
            .iter()
            .try_for_each(|deposit| processor.apply(&BridgeDeposit(deposit)))
    }
}

/// One contract deposit, applied by Electra's rule.
///
/// Phase0 credited the balance at once.
/// Electra queues the amount instead, so contract deposits share the churn with requests.
#[derive(Clone, Copy, Debug)]
pub struct BridgeDeposit<'a>(pub &'a Deposit);

impl<S: Fork + ParticipationState + PendingQueueState> Operation<S> for BridgeDeposit<'_> {
    /// Proves the deposit's inclusion, registers a new key, and queues the amount.
    ///
    /// A new key needs a valid proof of possession, or the deposit is dropped.
    /// The deposit is a valid part of the block either way, since the contract accepted it.
    ///
    /// The queued deposit carries the genesis slot.
    /// That slot marks it as bridged, so the queue never holds it back for finality.
    ///
    /// See `process_deposit` and `apply_deposit` in the Electra beacon chain spec.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        DepositInclusion(self.0).consume(&mut *processor.state.beacon)?;

        let data = &self.0.data;
        let deposit = PendingDeposit {
            pubkey: data.pubkey,
            withdrawal_credentials: data.withdrawal_credentials,
            amount: data.amount,
            signature: data.signature,
            slot: Slot::GENESIS,
        };
        let state = &mut processor.state;
        if state.validator_index(&data.pubkey).is_none() {
            let application = DepositApplication(&deposit);
            let skip = state.verification() == Verification::Skip;
            if !skip && !application.has_valid_signature(processor.config) {
                return Ok(());
            }
            // The key joins now with no balance; the amount waits in the queue.
            application.add_validator(state, Gwei::ZERO)?;
        }
        state
            .beacon
            .push_pending_deposit(deposit)
            .map_err(|source| StateError::Capacity {
                list: "pending deposits",
                source,
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, electra::BeaconState, phase0::Eth1Data};

    use super::*;

    fn state(deposit_count: u64, deposit_index: u64, start_index: u64) -> BeaconState<Minimal> {
        BeaconState {
            eth1_data: Eth1Data {
                deposit_count,
                ..Eth1Data::default()
            },
            eth1_deposit_index: deposit_index,
            deposit_requests_start_index: start_index,
            ..BeaconState::default()
        }
    }

    #[test]
    fn a_long_backlog_fills_the_block() {
        // Fixture state: 100 contract deposits, 10 bridged, requests not started.
        let state = state(100, 10, u64::MAX);

        // 90 remain, and the minimal preset caps a block at 16.
        assert_eq!(BridgeDeposits::expected_count(&state), 16);
    }

    #[test]
    fn the_first_request_cuts_the_backlog() {
        // Fixture state: 100 contract deposits, 10 bridged, requests from index 13.
        let state = state(100, 10, 13);

        // Only deposits 10, 11, and 12 come from the contract.
        assert_eq!(BridgeDeposits::expected_count(&state), 3);
    }

    #[test]
    fn a_finished_bridge_takes_no_deposit() {
        // Fixture state: 100 contract deposits, requests from index 13, 13 bridged.
        let state = state(100, 13, 13);

        // The bridge is done, so a block carries none.
        assert_eq!(BridgeDeposits::expected_count(&state), 0);
    }
}
