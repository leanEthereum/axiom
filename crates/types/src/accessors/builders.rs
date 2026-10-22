//! Builders and the split of block and payload, from Gloas on.

use crate::{
    BuilderIndex, Hash32,
    accessors::CoreState,
    gloas::{
        BuilderPendingPayments, BuilderPendingWithdrawals, Builders, ExecutionPayloadAvailability,
        ExecutionPayloadBid, PayloadTimelinessCommitteeWindow, Withdrawals,
    },
};

/// The builder registry, builder payments, and the state of the separated payload.
///
/// See EIP-7732 and the Gloas beacon chain spec.
pub trait BuilderState: CoreState {
    /// Hash of the latest execution block whose payload the chain accepted.
    fn latest_block_hash(&self) -> Hash32;

    /// Hash of the latest accepted execution block, for payload processing.
    fn latest_block_hash_mut(&mut self) -> &mut Hash32;

    /// The builder registry.
    fn builders(&self) -> &Builders;

    /// The builder registry, for deposits, exits, and payments.
    fn builders_mut(&mut self) -> &mut Builders;

    /// Builder the next withdrawal sweep starts at.
    fn next_withdrawal_builder_index(&self) -> BuilderIndex;

    /// Builder the next sweep starts at, for withdrawal processing.
    fn next_withdrawal_builder_index_mut(&mut self) -> &mut BuilderIndex;

    /// Whether each recent slot's payload arrived, a ring buffer indexed by slot.
    fn execution_payload_availability(&self) -> &ExecutionPayloadAvailability<Self::Preset>;

    /// Payload availability by slot, for slot and payload processing.
    fn execution_payload_availability_mut(
        &mut self,
    ) -> &mut ExecutionPayloadAvailability<Self::Preset>;

    /// Payments owed to builders for the previous and current epochs' bids.
    fn builder_pending_payments(&self) -> &BuilderPendingPayments<Self::Preset>;

    /// Payments owed to builders, for bids, slashings, and their epoch settlement.
    fn builder_pending_payments_mut(&mut self) -> &mut BuilderPendingPayments<Self::Preset>;

    /// Builder payments waiting to be withdrawn.
    fn builder_pending_withdrawals(&self) -> &BuilderPendingWithdrawals;

    /// Builder payments waiting to be withdrawn, for settlement and withdrawals.
    fn builder_pending_withdrawals_mut(&mut self) -> &mut BuilderPendingWithdrawals;

    /// The bid of the latest block, which its payload must honour.
    fn latest_execution_payload_bid(&self) -> &ExecutionPayloadBid;

    /// The bid of the latest block, for bid processing.
    fn latest_execution_payload_bid_mut(&mut self) -> &mut ExecutionPayloadBid;

    /// Withdrawals the next payload must carry, fixed when its block is processed.
    fn payload_expected_withdrawals(&self) -> &Withdrawals;

    /// Withdrawals the next payload must carry, for withdrawal processing.
    fn payload_expected_withdrawals_mut(&mut self) -> &mut Withdrawals;

    /// Payload timeliness committees of the previous, current, and next epochs.
    fn ptc_window(&self) -> &PayloadTimelinessCommitteeWindow<Self::Preset>;

    /// Payload timeliness committees, for the epoch shift.
    fn ptc_window_mut(&mut self) -> &mut PayloadTimelinessCommitteeWindow<Self::Preset>;
}
