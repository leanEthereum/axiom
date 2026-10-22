//! The beacon API's own messages: chain facts, registry views, duties, and preparations.
//!
//! These are no consensus containers, only the shapes the API defines around them.
//! See the types directory of `ethereum/beacon-APIs`.

mod chain;
mod duties;
mod preparation;
mod registry;

pub use chain::{Genesis, SyncStatus};
pub use duties::{AttesterDuty, Duties, ProposerDuty, PtcDuty, SyncDuty};
pub use preparation::{
    BeaconCommitteeSelection, BeaconCommitteeSubscription, ProposerPreparation,
    SyncCommitteeSelection, SyncCommitteeSubscription,
};
pub use registry::{Liveness, ValidatorResponse, ValidatorStatus};
