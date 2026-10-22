//! The vectors of phase0, the launch of the beacon chain.

use axiom_state_transition::phase0::block::AttestationRecord;
use axiom_types::{ForkName, Preset, phase0};

use super::SpecFork;
use crate::{Applied, Case, Failure, FieldNames, OperationInput};

/// The phase0 fork.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Phase0;

impl SpecFork for Phase0 {
    const FORK: ForkName = ForkName::Phase0;

    const STATE_FIELDS: FieldNames = FieldNames(&[
        "genesis_time",
        "genesis_validators_root",
        "slot",
        "fork",
        "latest_block_header",
        "block_roots",
        "state_roots",
        "historical_roots",
        "eth1_data",
        "eth1_data_votes",
        "eth1_deposit_index",
        "validators",
        "balances",
        "randao_mixes",
        "slashings",
        "previous_epoch_attestations",
        "current_epoch_attestations",
        "justification_bits",
        "previous_justified_checkpoint",
        "current_justified_checkpoint",
        "finalized_checkpoint",
    ]);

    type State<P: Preset> = phase0::BeaconState<P>;

    type SignedBeaconBlock<P: Preset> = phase0::SignedBeaconBlock<P>;

    fn operation<P: Preset>(
        handler: &str,
        input: &mut OperationInput<'_, '_, '_, phase0::BeaconState<P>>,
    ) -> Applied {
        match handler {
            "attestation" => input
                .apply_with::<phase0::Attestation<P>>("attestation", |attestation, processor| {
                    processor.apply(&AttestationRecord(attestation))
                }),
            "attester_slashing" => input.apply::<phase0::AttesterSlashing<P>>("attester_slashing"),
            "proposer_slashing" => input.apply::<phase0::ProposerSlashing>("proposer_slashing"),
            "deposit" => input.apply::<phase0::Deposit>("deposit"),
            "voluntary_exit" => input.apply::<phase0::SignedVoluntaryExit>("voluntary_exit"),
            "block_header" => input
                .apply_with::<phase0::BeaconBlock<P>>("block", |block, processor| {
                    processor.apply(&block.header())
                }),
            other => Err(Failure(format!("unsupported operation {other} in phase0"))),
        }
    }
    type BeaconBlockBody<P: Preset> = phase0::BeaconBlockBody<P>;

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
