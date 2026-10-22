//! The containers of Gloas: enshrined proposer-builder separation, see EIP-7732.
//!
//! A block carries a builder's bid, and the payload follows in a separate envelope.
//! Lists that grow with the chain become progressive, see EIP-7688.
//! Everything else is Fulu's.
//! See the Gloas beacon chain, networking, and light client specs.

mod aggregate;
mod attestation;
mod bid;
mod block;
mod block_contents;
mod builder;
mod data_column;
mod envelope;
mod execution;
mod light_client;
mod partial_column;
mod payload_attestation;
mod proposer_preferences;
mod state;

pub use aggregate::{AggregateAndProof, SignedAggregateAndProof};
pub use attestation::{
    AggregationBits, Attestation, AttesterSlashing, AttestingIndices, IndexedAttestation,
};
pub use bid::{ExecutionPayloadBid, SignedExecutionPayloadBid};
pub use block::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock};
pub use block_contents::BlockContents;
pub use builder::{
    Builder, BuilderDepositRequest, BuilderExitRequest, BuilderPendingPayment,
    BuilderPendingPayments, BuilderPendingWithdrawal, BuilderPendingWithdrawals, Builders,
};
pub use data_column::{DataColumn, DataColumnSidecar, KzgProofs};
pub use envelope::{ExecutionPayloadEnvelope, SignedExecutionPayloadEnvelope};
pub use execution::{
    BlobKzgCommitments, BlockAccessList, BuilderDepositRequests, BuilderExitRequests,
    ConsolidationRequests, DepositRequests, ExecutionPayload, ExecutionRequests, NewPayloadRequest,
    Transaction, Transactions, WithdrawalRequests, Withdrawals,
};
pub use light_client::{
    CurrentSyncCommitteeBranch, ExecutionBranch, FinalityBranch, LightClientBootstrap,
    LightClientFinalityUpdate, LightClientHeader, LightClientOptimisticUpdate, LightClientUpdate,
    NextSyncCommitteeBranch,
};
pub use partial_column::{
    CellsBitList, PartialDataColumnGroupId, PartialDataColumnPartsMetadata,
    PartialDataColumnSidecar,
};
pub use payload_attestation::{
    IndexedPayloadAttestation, PayloadAttestation, PayloadAttestationData,
    PayloadAttestationMessage, PayloadAttestations, PayloadTimelinessCommittee,
    PayloadTimelinessCommitteeBits, PayloadTimelinessCommitteeIndices,
    PayloadTimelinessCommitteeWindow,
};
pub use proposer_preferences::{ProposerPreferences, SignedProposerPreferences};
pub use state::{
    Balances, BeaconState, EpochParticipation, ExecutionPayloadAvailability, InactivityScores,
    PendingConsolidations, PendingDeposits, PendingPartialWithdrawals, Validators,
};

pub use crate::fulu::*;
