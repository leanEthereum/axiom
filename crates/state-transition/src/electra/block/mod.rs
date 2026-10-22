//! Block steps Electra introduced or rewrote, which later forks reuse.

mod attestation;
mod consolidation_request;
mod voluntary_exit;
mod withdrawal_request;
mod withdrawals;

pub use voluntary_exit::Exit;
pub use withdrawals::{ExpectedWithdrawals, PayloadWithdrawals};
