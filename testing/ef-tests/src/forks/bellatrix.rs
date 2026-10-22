//! The vectors of Bellatrix, the merge with the execution layer.

use axiom_gossip::GossipValidator;
use axiom_state_transition::{
    KnownVerdict,
    altair::block::{FlaggedAttestation, ParticipantDeposit},
    bellatrix::block::PayloadExecution,
};
use axiom_types::{ForkName, Preset, bellatrix};

use super::{Altair, SpecFork};
use crate::{Applied, Case, Failure, FieldNames, GossipMessage, OperationInput, Verdict};

/// The Bellatrix fork.
///
/// Containers its spec left unchanged are Altair's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bellatrix;

impl SpecFork for Bellatrix {
    const FORK: ForkName = ForkName::Bellatrix;

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
        "previous_epoch_participation",
        "current_epoch_participation",
        "justification_bits",
        "previous_justified_checkpoint",
        "current_justified_checkpoint",
        "finalized_checkpoint",
        "inactivity_scores",
        "current_sync_committee",
        "next_sync_committee",
        "latest_execution_payload_header",
    ]);

    type State<P: Preset> = bellatrix::BeaconState<P>;

    type SignedBeaconBlock<P: Preset> = bellatrix::SignedBeaconBlock<P>;

    type BeaconBlockBody<P: Preset> = bellatrix::BeaconBlockBody<P>;

    fn gossip<P: Preset>(
        topic: &str,
        message: &GossipMessage<'_>,
        validator: &mut GossipValidator<'_, '_, P>,
    ) -> Result<Verdict, Failure> {
        Altair::gossip(topic, message, validator)
    }

    fn ssz_static<P: Preset>(container: &str, case: &Case) -> Result<(), Failure> {
        match container {
            "BeaconBlock" => case.round_trip::<bellatrix::BeaconBlock<P>>(),
            "BeaconBlockBody" => case.round_trip::<bellatrix::BeaconBlockBody<P>>(),
            "BeaconState" => case.round_trip::<bellatrix::BeaconState<P>>(),
            "ExecutionPayload" => case.round_trip::<bellatrix::ExecutionPayload<P>>(),
            "ExecutionPayloadHeader" => case.round_trip::<bellatrix::ExecutionPayloadHeader<P>>(),
            "NewPayloadRequest" => case.round_trip::<bellatrix::NewPayloadRequest<P>>(),
            "PowBlock" => case.round_trip::<bellatrix::PowBlock>(),
            "SignedBeaconBlock" => case.round_trip::<bellatrix::SignedBeaconBlock<P>>(),
            _ => Altair::ssz_static::<P>(container, case),
        }
    }

    fn operation<P: Preset>(
        handler: &str,
        input: &mut OperationInput<'_, '_, '_, bellatrix::BeaconState<P>>,
    ) -> Applied {
        match handler {
            "attestation" => input.apply_with::<bellatrix::Attestation<P>>(
                "attestation",
                |attestation, processor| processor.apply(&FlaggedAttestation(attestation)),
            ),
            "attester_slashing" => {
                input.apply::<bellatrix::AttesterSlashing<P>>("attester_slashing")
            }
            "block_header" => input
                .apply_with::<bellatrix::BeaconBlock<P>>("block", |block, processor| {
                    processor.apply(&block.header())
                }),
            "deposit" => input.apply_with::<bellatrix::Deposit>("deposit", |deposit, processor| {
                processor.apply(&ParticipantDeposit(deposit))
            }),
            "execution_payload" => {
                let engine = KnownVerdict(input.execution_verdict()?);
                input.apply_with::<bellatrix::BeaconBlockBody<P>>("body", |body, processor| {
                    processor.apply(&PayloadExecution::new(body, &engine))
                })
            }
            "proposer_slashing" => input.apply::<bellatrix::ProposerSlashing>("proposer_slashing"),
            "sync_aggregate" => input.apply::<bellatrix::SyncAggregate<P>>("sync_aggregate"),
            "voluntary_exit" => input.apply::<bellatrix::SignedVoluntaryExit>("voluntary_exit"),
            other => Err(Failure(format!(
                "unsupported operation {other} in bellatrix"
            ))),
        }
    }
}
