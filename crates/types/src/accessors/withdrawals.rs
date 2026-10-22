//! Withdrawal cursors and historical summaries, from Capella on.

use crate::{ValidatorIndex, WithdrawalIndex, accessors::CoreState, capella::HistoricalSummaries};

/// Where the withdrawal sweep stands, and the summaries that replaced historical roots.
///
/// See the Capella beacon chain spec.
pub trait WithdrawalState: CoreState {
    /// Index the next withdrawal will get.
    fn next_withdrawal_index(&self) -> WithdrawalIndex;

    /// Index the next withdrawal will get, for withdrawal processing.
    fn next_withdrawal_index_mut(&mut self) -> &mut WithdrawalIndex;

    /// Validator the next withdrawal sweep starts at.
    fn next_withdrawal_validator_index(&self) -> ValidatorIndex;

    /// Validator the next sweep starts at, for withdrawal processing.
    fn next_withdrawal_validator_index_mut(&mut self) -> &mut ValidatorIndex;

    /// Summaries of every full period of block and state roots.
    fn historical_summaries(&self) -> &HistoricalSummaries<Self::Preset>;

    /// Summaries of every full period, for their epoch update.
    fn historical_summaries_mut(&mut self) -> &mut HistoricalSummaries<Self::Preset>;
}
