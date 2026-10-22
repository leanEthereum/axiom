//! Epoch steps Altair introduced or rewrote, which later forks reuse.

mod flag_rotation;
mod inactivity;
mod participation;
mod rewards;
mod sync_committees;

pub use flag_rotation::FlagRotation;
pub use inactivity::InactivityUpdates;
pub use participation::Participation;
pub use rewards::{Deltas, FlagReward, RewardsAndPenalties};
pub use sync_committees::SyncCommitteeRotation;
