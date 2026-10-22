//! Slashing protection: the EIP-3076 database and its interchange format.
//!
//! # Overview
//!
//! A validator is slashed for two blocks at one slot, or for two votes that conflict.
//! Votes conflict when they share a target or when one surrounds the other.
//! See `process_proposer_slashing` and `is_slashable_attestation_data` in the phase0 spec.
//!
//! The database records every block and vote before its signature exists.
//! It refuses any request that would form a slashable pair with a record.
//!
//! The interchange format moves this history between clients, so a key can migrate safely.

mod database;
mod error;
mod history;
mod interchange;
mod records;
mod surround;

pub use database::{ImportSummary, SlashingDatabase, VoteCheck};
pub use error::{InterchangeError, ProtectionError, Refusal};
pub use history::Safety;
pub use interchange::{Interchange, SignedAttestation, SignedBlock, ValidatorHistory};
