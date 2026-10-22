//! The vectors of Electra, which adds larger validators and execution requests.

use axiom_types::{ForkName, Preset, electra};

use super::{Deneb, SpecFork};
use crate::{Case, Failure};

/// The Electra fork.
///
/// Containers its spec left unchanged are Deneb's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Electra;

impl SpecFork for Electra {
    const FORK: ForkName = ForkName::Electra;

    fn ssz_static<P: Preset>(container: &str, case: &Case) -> Result<(), Failure> {
        match container {
            "AggregateAndProof" => case.round_trip::<electra::AggregateAndProof<P>>(),
            "Attestation" => case.round_trip::<electra::Attestation<P>>(),
            "AttesterSlashing" => case.round_trip::<electra::AttesterSlashing<P>>(),
            "BeaconBlock" => case.round_trip::<electra::BeaconBlock<P>>(),
            "BeaconBlockBody" => case.round_trip::<electra::BeaconBlockBody<P>>(),
            "BeaconState" => case.round_trip::<electra::BeaconState<P>>(),
            "ConsolidationRequest" => case.round_trip::<electra::ConsolidationRequest>(),
            "DepositRequest" => case.round_trip::<electra::DepositRequest>(),
            "ExecutionRequests" => case.round_trip::<electra::ExecutionRequests<P>>(),
            "IndexedAttestation" => case.round_trip::<electra::IndexedAttestation<P>>(),
            "LightClientBootstrap" => case.round_trip::<electra::LightClientBootstrap<P>>(),
            "LightClientFinalityUpdate" => {
                case.round_trip::<electra::LightClientFinalityUpdate<P>>()
            }
            "LightClientUpdate" => case.round_trip::<electra::LightClientUpdate<P>>(),
            "NewPayloadRequest" => case.round_trip::<electra::NewPayloadRequest<P>>(),
            "PendingConsolidation" => case.round_trip::<electra::PendingConsolidation>(),
            "PendingDeposit" => case.round_trip::<electra::PendingDeposit>(),
            "PendingPartialWithdrawal" => case.round_trip::<electra::PendingPartialWithdrawal>(),
            "SignedAggregateAndProof" => case.round_trip::<electra::SignedAggregateAndProof<P>>(),
            "SignedBeaconBlock" => case.round_trip::<electra::SignedBeaconBlock<P>>(),
            "SingleAttestation" => case.round_trip::<electra::SingleAttestation>(),
            "WithdrawalRequest" => case.round_trip::<electra::WithdrawalRequest>(),
            _ => Deneb::ssz_static::<P>(container, case),
        }
    }
}
