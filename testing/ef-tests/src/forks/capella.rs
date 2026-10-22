//! The vectors of Capella, which adds withdrawals.

use axiom_gossip::GossipValidator;
use axiom_state_transition::{
    KnownVerdict,
    altair::block::{FlaggedAttestation, ParticipantDeposit},
    capella::block::{PayloadExecution, PayloadWithdrawals},
};
use axiom_types::{ForkName, Preset, capella};

use super::{Bellatrix, SpecFork};
use crate::{Applied, Case, Failure, FieldNames, GossipMessage, OperationInput, Verdict};

/// The Capella fork.
///
/// Containers its spec left unchanged are Bellatrix's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capella;

impl SpecFork for Capella {
    const FORK: ForkName = ForkName::Capella;

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
        "next_withdrawal_index",
        "next_withdrawal_validator_index",
        "historical_summaries",
    ]);

    type State<P: Preset> = capella::BeaconState<P>;

    type SignedBeaconBlock<P: Preset> = capella::SignedBeaconBlock<P>;

    type BeaconBlockBody<P: Preset> = capella::BeaconBlockBody<P>;

    fn gossip<P: Preset>(
        topic: &str,
        message: &GossipMessage<'_>,
        validator: &mut GossipValidator<'_, '_, P>,
    ) -> Result<Verdict, Failure> {
        match topic {
            "bls_to_execution_change" => Ok(validator.bls_to_execution_change(
                &message.decode::<capella::SignedBlsToExecutionChange>()?,
                message.now_ms(),
            )),
            _ => Bellatrix::gossip(topic, message, validator),
        }
    }

    fn ssz_static<P: Preset>(container: &str, case: &Case) -> Result<(), Failure> {
        match container {
            "BLSToExecutionChange" => case.round_trip::<capella::BlsToExecutionChange>(),
            "BeaconBlock" => case.round_trip::<capella::BeaconBlock<P>>(),
            "BeaconBlockBody" => case.round_trip::<capella::BeaconBlockBody<P>>(),
            "BeaconState" => case.round_trip::<capella::BeaconState<P>>(),
            "ExecutionPayload" => case.round_trip::<capella::ExecutionPayload<P>>(),
            "ExecutionPayloadHeader" => case.round_trip::<capella::ExecutionPayloadHeader<P>>(),
            "HistoricalSummary" => case.round_trip::<capella::HistoricalSummary>(),
            "LightClientBootstrap" => case.round_trip::<capella::LightClientBootstrap<P>>(),
            "LightClientFinalityUpdate" => {
                case.round_trip::<capella::LightClientFinalityUpdate<P>>()
            }
            "LightClientHeader" => case.round_trip::<capella::LightClientHeader<P>>(),
            "LightClientOptimisticUpdate" => {
                case.round_trip::<capella::LightClientOptimisticUpdate<P>>()
            }
            "LightClientUpdate" => case.round_trip::<capella::LightClientUpdate<P>>(),
            "NewPayloadRequest" => case.round_trip::<capella::NewPayloadRequest<P>>(),
            "SignedBLSToExecutionChange" => {
                case.round_trip::<capella::SignedBlsToExecutionChange>()
            }
            "SignedBeaconBlock" => case.round_trip::<capella::SignedBeaconBlock<P>>(),
            "Withdrawal" => case.round_trip::<capella::Withdrawal>(),
            _ => Bellatrix::ssz_static::<P>(container, case),
        }
    }

    fn operation<P: Preset>(
        handler: &str,
        input: &mut OperationInput<'_, '_, '_, capella::BeaconState<P>>,
    ) -> Applied {
        match handler {
            "attestation" => input
                .apply_with::<capella::Attestation<P>>("attestation", |attestation, processor| {
                    processor.apply(&FlaggedAttestation(attestation))
                }),
            "attester_slashing" => input.apply::<capella::AttesterSlashing<P>>("attester_slashing"),
            "proposer_slashing" => input.apply::<capella::ProposerSlashing>("proposer_slashing"),
            "deposit" => input.apply_with::<capella::Deposit>("deposit", |deposit, processor| {
                processor.apply(&ParticipantDeposit(deposit))
            }),
            "voluntary_exit" => input.apply::<capella::SignedVoluntaryExit>("voluntary_exit"),
            "bls_to_execution_change" => {
                input.apply::<capella::SignedBlsToExecutionChange>("address_change")
            }
            "block_header" => input
                .apply_with::<capella::BeaconBlock<P>>("block", |block, processor| {
                    processor.apply(&block.header())
                }),
            "sync_aggregate" => input.apply::<capella::SyncAggregate<P>>("sync_aggregate"),
            "withdrawals" => input.apply_with::<capella::ExecutionPayload<P>>(
                "execution_payload",
                |payload, processor| processor.apply(&PayloadWithdrawals(&payload.withdrawals)),
            ),
            "execution_payload" => {
                let engine = KnownVerdict(input.execution_verdict()?);
                input.apply_with::<capella::BeaconBlockBody<P>>("body", |body, processor| {
                    processor.apply(&PayloadExecution::new(&body.execution_payload, &engine))
                })
            }
            other => Err(Failure(format!("unsupported operation {other} in capella"))),
        }
    }
}
