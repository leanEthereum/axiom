//! Block steps Gloas introduced or rewrote.
//!
//! The bid, payload attestations, and builder requests are Gloas types, so they apply as they are.
//! Attestations need the parent's slot, so they apply through a wrapper.

mod attestation;
mod bid;
mod body_limits;
mod builder_deposit_request;
mod builder_exit_request;
mod parent_payload;
mod payload_attestation;
mod withdrawals;

pub use attestation::IncludedAttestation;
pub use body_limits::BodyLimits;
pub use parent_payload::{ParentPayload, ParentRequests};
pub use withdrawals::{CommittedWithdrawals, ExpectedWithdrawals};
