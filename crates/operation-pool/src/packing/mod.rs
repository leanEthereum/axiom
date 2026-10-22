//! Choosing what a block carries from the pools.

mod attestations;
mod ledger;

pub use attestations::{AttestationPacker, Eligibility, PackedAttestation};
pub use ledger::{FLAGS, Ledger, RewardRule};
