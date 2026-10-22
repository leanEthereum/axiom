//! The containers of Altair: sync committees and participation flags.
//!
//! Everything else is phase0's.
//! See the Altair beacon chain, validator, and light client specs.

mod block;
mod light_client;
mod state;
mod sync_committee;

pub use block::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock};
pub use light_client::{
    CurrentSyncCommitteeBranch, FinalityBranch, LightClientBootstrap, LightClientFinalityUpdate,
    LightClientHeader, LightClientOptimisticUpdate, LightClientUpdate, NextSyncCommitteeBranch,
};
pub use state::{BeaconState, EpochParticipation, InactivityScores};
pub use sync_committee::{
    ContributionAndProof, SignedContributionAndProof, SyncAggregate, SyncAggregatorSelectionData,
    SyncCommittee, SyncCommitteeBits, SyncCommitteeContribution, SyncCommitteeMessage,
    SyncSubcommitteeBits,
};

pub use crate::phase0::*;
