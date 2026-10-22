//! The slasher: finds validators that broke a slashing condition, and builds the evidence.
//!
//! # Overview
//!
//! A validator is slashable for three offences.
//!
//! - A double proposal: two different headers for one slot.
//! - A double vote: two different votes for one target epoch.
//! - A surround vote: one vote whose source and target both lie strictly outside another's.
//!
//! See `process_proposer_slashing` and `is_slashable_attestation_data` in the phase0 spec.
//!
//! The node hands over every verified vote and header it sees, from gossip and from blocks.
//! A pass then compares them with the history of the last few thousand epochs.
//! Evidence leaves fork-neutral; the operation pool puts it in the container of its block's fork.
//!
//! # Performance
//!
//! Surround votes are found with min-max span arrays, at a constant cost per vote.
//! The arrays sit on disk in compressed chunks, and a pass touches only the chunks it needs.
//! Votes are stored once per distinct vote, and only when a validator's record names them.
//!
//! The detection core does no input or output of its own.
//! It reads chunks through the database adapter, and stages every write in one batch.

mod attestations;
mod chunk;
mod config;
mod database;
mod error;
mod proposals;
mod records;
mod signers;
mod slasher;
mod span;

pub use config::{Geometry, SlasherConfig};
pub use database::SlasherDatabase;
pub use error::{ConfigError, SlasherError};
pub use slasher::{Pass, Slasher, Slashing};
