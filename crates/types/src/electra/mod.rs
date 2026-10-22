//! The containers of Electra: larger validators and execution requests.
//!
//! See EIP-7251, EIP-7002, EIP-6110, EIP-7549, and EIP-7685.
//! Everything else is Deneb's.
//! See the Electra beacon chain, validator, and light client specs.

mod aggregate;
mod attestation;
mod blinded_block;
mod block;
mod block_contents;
mod builder;
mod consolidation;
mod deposit;
mod execution;
mod light_client;
mod slashing;
mod state;
mod withdrawal;

pub use aggregate::{AggregateAndProof, SignedAggregateAndProof};
pub use attestation::{
    AggregationBits, Attestation, AttestingIndices, CommitteeBits, IndexedAttestation,
    SingleAttestation,
};
pub use blinded_block::{BlindedBeaconBlock, BlindedBeaconBlockBody, SignedBlindedBeaconBlock};
pub use block::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock};
pub use block_contents::{BlockContents, SignedBlockContents};
pub use builder::{BuilderBid, SignedBuilderBid};
pub use consolidation::{ConsolidationRequest, PendingConsolidation};
pub use deposit::{DepositRequest, PendingDeposit};
pub use execution::{
    ConsolidationRequests, DepositRequests, ExecutionRequests, NewPayloadRequest,
    WithdrawalRequests,
};
pub use light_client::{
    CurrentSyncCommitteeBranch, FinalityBranch, LightClientBootstrap, LightClientFinalityUpdate,
    LightClientUpdate, NextSyncCommitteeBranch,
};
pub use slashing::AttesterSlashing;
pub use state::{BeaconState, PendingConsolidations, PendingDeposits, PendingPartialWithdrawals};
pub use withdrawal::{PendingPartialWithdrawal, WithdrawalRequest};

pub use crate::deneb::*;
