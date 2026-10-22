//! Block steps phase0 introduced, which later forks reuse until they rewrite them.

mod attestation;
mod attester_slashing;
mod deposit;
mod deposit_inclusion;
mod eth1_data;
mod header;
mod proposer_slashing;
mod randao;
mod voluntary_exit;

pub use attestation::AttestationRecord;
pub use deposit::{ContractDeposit, DepositQuota};
pub use deposit_inclusion::DepositInclusion;
pub use randao::RandaoReveal;
pub use voluntary_exit::SignedExit;
