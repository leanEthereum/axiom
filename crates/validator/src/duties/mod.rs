//! Duties: proposals, attestations, aggregation, sync committees, and payload timeliness.
//!
//! # Overview
//!
//! Every duty follows the honest validator specs of its fork, timed by the injected clock.
//!
//! - A proposer builds at the start of its slot.
//! - Attesters and sync members sign at their deadlines, a third of the slot before Gloas.
//! - Aggregators sign at the next deadline, two thirds of the slot before Gloas.
//! - Payload timeliness members vote at three quarters of a Gloas slot.
//!
//! Each duty reads its fork from the slot once, and builds that fork's messages.
//! Every signature goes through the validator store, so through slashing protection.

mod attester;
mod book;
mod context;
mod doppelganger;
mod error;
mod preparation;
mod proposer;
mod ptc;
mod schedule;
mod selection;
mod service;
mod sync;
mod timing;

pub use attester::Attester;
pub use book::{AttesterSeat, DutyBook};
pub use context::{ClientSettings, DutyContext};
pub use doppelganger::Doppelganger;
pub use error::DutyError;
pub use preparation::Preparation;
pub use proposer::BlockProposer;
pub use ptc::PayloadTimeliness;
pub use schedule::DutyScheduler;
pub use selection::AggregatorSelection;
pub use service::ValidatorClient;
pub use sync::SyncCommittee;
pub use timing::SlotTimer;
