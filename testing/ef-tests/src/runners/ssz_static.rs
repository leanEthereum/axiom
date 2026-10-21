//! SSZ static vectors: every container round-trips and hashes to the expected root.

use std::marker::PhantomData;

use axiom_ssz::{Root, Ssz};
use axiom_types::{
    AggregateAndProof, Attestation, AttestationData, AttesterSlashing, BeaconBlock,
    BeaconBlockBody, BeaconBlockHeader, BeaconState, BlobIdentifier, BlobSidecar,
    BlsToExecutionChange, Checkpoint, ConsolidationRequest, ContributionAndProof,
    DataColumnSidecar, DataColumnsByRootIdentifier, Deposit, DepositData, DepositMessage,
    DepositRequest, Eth1Block, Eth1Data, ExecutionPayload, ExecutionPayloadHeader,
    ExecutionRequests, Fork, ForkData, HistoricalBatch, HistoricalSummary, IndexedAttestation,
    LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
    LightClientOptimisticUpdate, LightClientUpdate, MatrixEntry, NewPayloadRequest,
    PartialDataColumnGroupId, PartialDataColumnHeader, PartialDataColumnPartsMetadata,
    PartialDataColumnSidecar, PendingConsolidation, PendingDeposit, PendingPartialWithdrawal,
    PowBlock, Preset, ProposerSlashing, SignedAggregateAndProof, SignedBeaconBlock,
    SignedBeaconBlockHeader, SignedBlsToExecutionChange, SignedContributionAndProof,
    SignedVoluntaryExit, SigningData, SingleAttestation, SyncAggregate,
    SyncAggregatorSelectionData, SyncCommittee, SyncCommitteeContribution, SyncCommitteeMessage,
    Validator, VoluntaryExit, Withdrawal, WithdrawalRequest,
};

use crate::{Case, Failure, Runner};

/// Decodes each container's vector, then checks its root and its re-encoding.
#[derive(Debug, Default)]
pub struct SszStatic<P>(PhantomData<P>);

impl<P: Preset> SszStatic<P> {
    /// Checks one container type against a case.
    fn check<T: Ssz>(case: &Case) -> Result<(), Failure> {
        let bytes = case.ssz_bytes("serialized")?;
        let value =
            T::decode(&bytes).map_err(|error| Failure(format!("decode failed: {error}")))?;

        let expected = case
            .yaml("roots.yaml")?
            .get("root")
            .and_then(|root| root.as_hex_array::<32>())
            .ok_or_else(|| Failure::new("roots.yaml has no root"))?;
        let root = value.hash_tree_root();
        if root != Root(expected) {
            return Err(Failure(format!("root {root} is not {}", Root(expected))));
        }
        if value.encode() != bytes {
            return Err(Failure::new("re-encoding differs from the vector"));
        }
        Ok(())
    }
}

impl<P: Preset> Runner for SszStatic<P> {
    fn name(&self) -> &'static str {
        "ssz_static"
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        match handler {
            "AggregateAndProof" => Self::check::<AggregateAndProof<P>>(case),
            "Attestation" => Self::check::<Attestation<P>>(case),
            "AttestationData" => Self::check::<AttestationData>(case),
            "AttesterSlashing" => Self::check::<AttesterSlashing<P>>(case),
            "BLSToExecutionChange" => Self::check::<BlsToExecutionChange>(case),
            "BeaconBlock" => Self::check::<BeaconBlock<P>>(case),
            "BeaconBlockBody" => Self::check::<BeaconBlockBody<P>>(case),
            "BeaconBlockHeader" => Self::check::<BeaconBlockHeader>(case),
            "BeaconState" => Self::check::<BeaconState<P>>(case),
            "Checkpoint" => Self::check::<Checkpoint>(case),
            "ConsolidationRequest" => Self::check::<ConsolidationRequest>(case),
            "ContributionAndProof" => Self::check::<ContributionAndProof<P>>(case),
            "DataColumnSidecar" => Self::check::<DataColumnSidecar<P>>(case),
            "DataColumnsByRootIdentifier" => Self::check::<DataColumnsByRootIdentifier<P>>(case),
            "Deposit" => Self::check::<Deposit>(case),
            "DepositData" => Self::check::<DepositData>(case),
            "DepositMessage" => Self::check::<DepositMessage>(case),
            "DepositRequest" => Self::check::<DepositRequest>(case),
            "Eth1Block" => Self::check::<Eth1Block>(case),
            "Eth1Data" => Self::check::<Eth1Data>(case),
            "ExecutionPayload" => Self::check::<ExecutionPayload<P>>(case),
            "ExecutionPayloadHeader" => Self::check::<ExecutionPayloadHeader<P>>(case),
            "ExecutionRequests" => Self::check::<ExecutionRequests<P>>(case),
            "Fork" => Self::check::<Fork>(case),
            "ForkData" => Self::check::<ForkData>(case),
            "HistoricalSummary" => Self::check::<HistoricalSummary>(case),
            "IndexedAttestation" => Self::check::<IndexedAttestation<P>>(case),
            "LightClientBootstrap" => Self::check::<LightClientBootstrap<P>>(case),
            "LightClientFinalityUpdate" => Self::check::<LightClientFinalityUpdate<P>>(case),
            "LightClientHeader" => Self::check::<LightClientHeader<P>>(case),
            "LightClientOptimisticUpdate" => Self::check::<LightClientOptimisticUpdate<P>>(case),
            "LightClientUpdate" => Self::check::<LightClientUpdate<P>>(case),
            "MatrixEntry" => Self::check::<MatrixEntry<P>>(case),
            "NewPayloadRequest" => Self::check::<NewPayloadRequest<P>>(case),
            "PartialDataColumnGroupID" => Self::check::<PartialDataColumnGroupId>(case),
            "PartialDataColumnHeader" => Self::check::<PartialDataColumnHeader<P>>(case),
            "PartialDataColumnPartsMetadata" => {
                Self::check::<PartialDataColumnPartsMetadata<P>>(case)
            }
            "PartialDataColumnSidecar" => Self::check::<PartialDataColumnSidecar<P>>(case),
            "PendingConsolidation" => Self::check::<PendingConsolidation>(case),
            "PendingDeposit" => Self::check::<PendingDeposit>(case),
            "PendingPartialWithdrawal" => Self::check::<PendingPartialWithdrawal>(case),
            "PowBlock" => Self::check::<PowBlock>(case),
            "ProposerSlashing" => Self::check::<ProposerSlashing>(case),
            "SignedAggregateAndProof" => Self::check::<SignedAggregateAndProof<P>>(case),
            "SignedBLSToExecutionChange" => Self::check::<SignedBlsToExecutionChange>(case),
            "SignedBeaconBlock" => Self::check::<SignedBeaconBlock<P>>(case),
            "SignedBeaconBlockHeader" => Self::check::<SignedBeaconBlockHeader>(case),
            "SignedContributionAndProof" => Self::check::<SignedContributionAndProof<P>>(case),
            "SignedVoluntaryExit" => Self::check::<SignedVoluntaryExit>(case),
            "SigningData" => Self::check::<SigningData>(case),
            "SingleAttestation" => Self::check::<SingleAttestation>(case),
            "SyncAggregate" => Self::check::<SyncAggregate<P>>(case),
            "SyncAggregatorSelectionData" => Self::check::<SyncAggregatorSelectionData>(case),
            "SyncCommittee" => Self::check::<SyncCommittee<P>>(case),
            "SyncCommitteeContribution" => Self::check::<SyncCommitteeContribution<P>>(case),
            "SyncCommitteeMessage" => Self::check::<SyncCommitteeMessage>(case),
            "Validator" => Self::check::<Validator>(case),
            "VoluntaryExit" => Self::check::<VoluntaryExit>(case),
            "Withdrawal" => Self::check::<Withdrawal>(case),
            "WithdrawalRequest" => Self::check::<WithdrawalRequest>(case),
            "HistoricalBatch" => Self::check::<HistoricalBatch<P>>(case),
            "BlobIdentifier" => Self::check::<BlobIdentifier>(case),
            "BlobSidecar" => Self::check::<BlobSidecar<P>>(case),
            other => Err(Failure(format!("unsupported type {other}"))),
        }
    }
}
