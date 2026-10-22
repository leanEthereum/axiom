//! Block steps Electra introduced or rewrote, which later forks reuse.

mod attestation;
mod consolidation_request;
mod deposit;
mod deposit_request;
mod execution_payload;
mod voluntary_exit;
mod withdrawal_request;
mod withdrawals;

pub use deposit::{BridgeDeposit, BridgeDeposits};
pub use deposit_request::RequestedDeposit;
pub use execution_payload::PayloadExecution;
pub use voluntary_exit::Exit;
pub(crate) use withdrawals::WithdrawalPlan;
pub use withdrawals::{ExpectedWithdrawals, PayloadWithdrawals};
