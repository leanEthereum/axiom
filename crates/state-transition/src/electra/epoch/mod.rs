//! Epoch steps Electra introduced or rewrote, which later forks reuse.

mod effective_balance;
mod pending_consolidations;
mod pending_deposits;
mod registry_updates;
mod slashings;

pub use effective_balance::Hysteresis;
pub use pending_consolidations::ConsolidationQueue;
pub use pending_deposits::DepositQueue;
pub use registry_updates::RegistryUpdates;
pub use slashings::CorrelationPenalty;
