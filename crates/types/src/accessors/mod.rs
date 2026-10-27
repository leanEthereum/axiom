//! Accessor traits over the beacon states of every fork, one per field group.
//!
//! # Overview
//!
//! Nine forks define nine state structs.
//! Code that reads or writes a group of fields should not care which struct holds them.
//! Each trait here names one such group, and each state implements exactly the groups it has.
//!
//! The groups follow the fields, not the fork order.
//! Gloas drops the execution payload header, so no trait implies all earlier ones.
//!
//! ```text
//! group               phase0  altair  bellatrix  capella  deneb  electra  fulu  gloas  hstar
//! core                yes     yes     yes        yes      yes    yes      yes   yes    yes
//! participation       -       yes     yes        yes      yes    yes      yes   yes    yes
//! sync committees     -       yes     yes        yes      yes    yes      yes   yes    yes
//! execution header    -       -       yes        yes      yes    yes      yes   -      -
//! withdrawals         -       -       -          yes      yes    yes      yes   yes    yes
//! pending queues      -       -       -          -        -      yes      yes   yes    yes
//! proposer lookahead  -       -       -          -        -      -        yes   yes    yes
//! builders            -       -       -          -        -      -        -     yes    yes
//! pq key registry     -       -       -          -        -      -        -     -      yes
//! ```
//!
//! # Invariants
//!
//! Lists the registry indexes, such as balances and participation, hand out slices.
//! Growing them goes through methods that grow every parallel list at once.
//! The lists therefore never disagree on the registry size.

mod base;
mod builders;
mod execution;
mod lookahead;
mod participation;
mod pending_queues;
mod pq_registry;
mod sync_committees;
mod withdrawals;

pub use base::{CoreState, ForkState};
pub use builders::BuilderState;
pub use execution::ExecutionHeaderState;
pub use lookahead::LookaheadState;
pub use participation::ParticipationState;
pub use pending_queues::PendingQueueState;
pub use pq_registry::PqRegistryState;
pub use sync_committees::SyncCommitteeState;
pub use withdrawals::WithdrawalState;
