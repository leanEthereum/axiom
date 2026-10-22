//! Block steps Altair introduced or rewrote, which later forks reuse.

mod attestation;
mod deposit;
mod sync_aggregate;

pub use attestation::{FlaggedAttestation, ParticipationCredit};
pub use deposit::ParticipantDeposit;
pub use sync_aggregate::SyncRewardRates;
