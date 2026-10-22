//! The vectors of phase0, the launch of the beacon chain.

use axiom_types::{ForkName, Preset, phase0};

use super::SpecFork;
use crate::{Case, Failure};

/// The phase0 fork.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Phase0;

impl SpecFork for Phase0 {
    const FORK: ForkName = ForkName::Phase0;

    fn ssz_static<P: Preset>(container: &str, case: &Case) -> Result<(), Failure> {
        match container {
            "AggregateAndProof" => case.round_trip::<phase0::AggregateAndProof<P>>(),
            "Attestation" => case.round_trip::<phase0::Attestation<P>>(),
            "AttestationData" => case.round_trip::<phase0::AttestationData>(),
            "AttesterSlashing" => case.round_trip::<phase0::AttesterSlashing<P>>(),
            "BeaconBlock" => case.round_trip::<phase0::BeaconBlock<P>>(),
            "BeaconBlockBody" => case.round_trip::<phase0::BeaconBlockBody<P>>(),
            "BeaconBlockHeader" => case.round_trip::<phase0::BeaconBlockHeader>(),
            "BeaconState" => case.round_trip::<phase0::BeaconState<P>>(),
            "Checkpoint" => case.round_trip::<phase0::Checkpoint>(),
            "Deposit" => case.round_trip::<phase0::Deposit>(),
            "DepositData" => case.round_trip::<phase0::DepositData>(),
            "DepositMessage" => case.round_trip::<phase0::DepositMessage>(),
            "Eth1Block" => case.round_trip::<phase0::Eth1Block>(),
            "Eth1Data" => case.round_trip::<phase0::Eth1Data>(),
            "Fork" => case.round_trip::<phase0::Fork>(),
            "ForkData" => case.round_trip::<phase0::ForkData>(),
            "HistoricalBatch" => case.round_trip::<phase0::HistoricalBatch<P>>(),
            "IndexedAttestation" => case.round_trip::<phase0::IndexedAttestation<P>>(),
            "PendingAttestation" => case.round_trip::<phase0::PendingAttestation<P>>(),
            "ProposerSlashing" => case.round_trip::<phase0::ProposerSlashing>(),
            "SignedAggregateAndProof" => case.round_trip::<phase0::SignedAggregateAndProof<P>>(),
            "SignedBeaconBlock" => case.round_trip::<phase0::SignedBeaconBlock<P>>(),
            "SignedBeaconBlockHeader" => case.round_trip::<phase0::SignedBeaconBlockHeader>(),
            "SignedVoluntaryExit" => case.round_trip::<phase0::SignedVoluntaryExit>(),
            "SigningData" => case.round_trip::<phase0::SigningData>(),
            "Validator" => case.round_trip::<phase0::Validator>(),
            "VoluntaryExit" => case.round_trip::<phase0::VoluntaryExit>(),
            other => Err(Failure(format!("unknown container {other}"))),
        }
    }
}
