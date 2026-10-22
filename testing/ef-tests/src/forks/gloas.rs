//! The vectors of Gloas, which enshrines proposer-builder separation.

use axiom_types::{ForkName, Preset, gloas};

use super::{Fulu, SpecFork};
use crate::{Case, Failure};

/// The Gloas fork.
///
/// Containers its spec left unchanged are Fulu's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gloas;

impl SpecFork for Gloas {
    const FORK: ForkName = ForkName::Gloas;

    fn ssz_static<P: Preset>(container: &str, case: &Case) -> Result<(), Failure> {
        match container {
            "AggregateAndProof" => case.round_trip::<gloas::AggregateAndProof<P>>(),
            "Attestation" => case.round_trip::<gloas::Attestation<P>>(),
            "AttesterSlashing" => case.round_trip::<gloas::AttesterSlashing>(),
            "BeaconBlock" => case.round_trip::<gloas::BeaconBlock<P>>(),
            "BeaconBlockBody" => case.round_trip::<gloas::BeaconBlockBody<P>>(),
            "BeaconState" => case.round_trip::<gloas::BeaconState<P>>(),
            "Builder" => case.round_trip::<gloas::Builder>(),
            "BuilderDepositRequest" => case.round_trip::<gloas::BuilderDepositRequest>(),
            "BuilderExitRequest" => case.round_trip::<gloas::BuilderExitRequest>(),
            "BuilderPendingPayment" => case.round_trip::<gloas::BuilderPendingPayment>(),
            "BuilderPendingWithdrawal" => case.round_trip::<gloas::BuilderPendingWithdrawal>(),
            "DataColumnSidecar" => case.round_trip::<gloas::DataColumnSidecar<P>>(),
            "ExecutionPayload" => case.round_trip::<gloas::ExecutionPayload<P>>(),
            "ExecutionPayloadBid" => case.round_trip::<gloas::ExecutionPayloadBid>(),
            "ExecutionPayloadEnvelope" => case.round_trip::<gloas::ExecutionPayloadEnvelope<P>>(),
            "ExecutionRequests" => case.round_trip::<gloas::ExecutionRequests>(),
            "IndexedAttestation" => case.round_trip::<gloas::IndexedAttestation>(),
            "IndexedPayloadAttestation" => case.round_trip::<gloas::IndexedPayloadAttestation<P>>(),
            "LightClientBootstrap" => case.round_trip::<gloas::LightClientBootstrap<P>>(),
            "LightClientFinalityUpdate" => case.round_trip::<gloas::LightClientFinalityUpdate<P>>(),
            "LightClientHeader" => case.round_trip::<gloas::LightClientHeader>(),
            "LightClientOptimisticUpdate" => {
                case.round_trip::<gloas::LightClientOptimisticUpdate<P>>()
            }
            "LightClientUpdate" => case.round_trip::<gloas::LightClientUpdate<P>>(),
            "NewPayloadRequest" => case.round_trip::<gloas::NewPayloadRequest<P>>(),
            "PartialDataColumnGroupID" => case.round_trip::<gloas::PartialDataColumnGroupId>(),
            "PartialDataColumnPartsMetadata" => {
                case.round_trip::<gloas::PartialDataColumnPartsMetadata>()
            }
            "PartialDataColumnSidecar" => case.round_trip::<gloas::PartialDataColumnSidecar<P>>(),
            "PayloadAttestation" => case.round_trip::<gloas::PayloadAttestation<P>>(),
            "PayloadAttestationData" => case.round_trip::<gloas::PayloadAttestationData>(),
            "PayloadAttestationMessage" => case.round_trip::<gloas::PayloadAttestationMessage>(),
            "ProposerPreferences" => case.round_trip::<gloas::ProposerPreferences>(),
            "SignedAggregateAndProof" => case.round_trip::<gloas::SignedAggregateAndProof<P>>(),
            "SignedBeaconBlock" => case.round_trip::<gloas::SignedBeaconBlock<P>>(),
            "SignedExecutionPayloadBid" => case.round_trip::<gloas::SignedExecutionPayloadBid>(),
            "SignedExecutionPayloadEnvelope" => {
                case.round_trip::<gloas::SignedExecutionPayloadEnvelope<P>>()
            }
            "SignedProposerPreferences" => case.round_trip::<gloas::SignedProposerPreferences>(),
            _ => Fulu::ssz_static::<P>(container, case),
        }
    }
}
