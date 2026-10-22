//! The vectors of Deneb, which adds blobs.

use axiom_gossip::{BlobSubnets, GossipValidator};
use axiom_kzg::Kzg;
use axiom_state_transition::{
    KnownVerdict,
    altair::block::ParticipantDeposit,
    capella::block::PayloadWithdrawals,
    deneb::block::{Exit, PayloadExecution, UnboundedAttestation},
};
use axiom_types::{ForkName, Preset, deneb};

use super::{Capella, SpecFork};
use crate::{Applied, Case, Failure, FieldNames, GossipMessage, OperationInput, Verdict};

/// The Deneb fork.
///
/// Containers its spec left unchanged are Capella's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Deneb;

impl SpecFork for Deneb {
    const FORK: ForkName = ForkName::Deneb;

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

    type State<P: Preset> = deneb::BeaconState<P>;

    type SignedBeaconBlock<P: Preset> = deneb::SignedBeaconBlock<P>;

    type BeaconBlockBody<P: Preset> = deneb::BeaconBlockBody<P>;

    fn gossip<P: Preset>(
        topic: &str,
        message: &GossipMessage<'_>,
        validator: &mut GossipValidator<'_, '_, P>,
    ) -> Result<Verdict, Failure> {
        match topic {
            "blob_sidecar" => {
                let limits = BlobSubnets::deneb(validator.config());
                Ok(validator.blob_sidecar(
                    &message.decode::<deneb::BlobSidecar<P>>()?,
                    message.now_ms(),
                    message.subnet(),
                    limits,
                    Kzg::mainnet(),
                ))
            }
            _ => Capella::gossip(topic, message, validator),
        }
    }

    fn ssz_static<P: Preset>(container: &str, case: &Case) -> Result<(), Failure> {
        match container {
            "BeaconBlock" => case.round_trip::<deneb::BeaconBlock<P>>(),
            "BeaconBlockBody" => case.round_trip::<deneb::BeaconBlockBody<P>>(),
            "BeaconState" => case.round_trip::<deneb::BeaconState<P>>(),
            "BlobIdentifier" => case.round_trip::<deneb::BlobIdentifier>(),
            "BlobSidecar" => case.round_trip::<deneb::BlobSidecar<P>>(),
            "ExecutionPayload" => case.round_trip::<deneb::ExecutionPayload<P>>(),
            "ExecutionPayloadHeader" => case.round_trip::<deneb::ExecutionPayloadHeader<P>>(),
            "LightClientBootstrap" => case.round_trip::<deneb::LightClientBootstrap<P>>(),
            "LightClientFinalityUpdate" => case.round_trip::<deneb::LightClientFinalityUpdate<P>>(),
            "LightClientHeader" => case.round_trip::<deneb::LightClientHeader<P>>(),
            "LightClientOptimisticUpdate" => {
                case.round_trip::<deneb::LightClientOptimisticUpdate<P>>()
            }
            "LightClientUpdate" => case.round_trip::<deneb::LightClientUpdate<P>>(),
            "NewPayloadRequest" => case.round_trip::<deneb::NewPayloadRequest<P>>(),
            "SignedBeaconBlock" => case.round_trip::<deneb::SignedBeaconBlock<P>>(),
            _ => Capella::ssz_static::<P>(container, case),
        }
    }

    fn operation<P: Preset>(
        handler: &str,
        input: &mut OperationInput<'_, '_, '_, deneb::BeaconState<P>>,
    ) -> Applied {
        match handler {
            "attestation" => input
                .apply_with::<deneb::Attestation<P>>("attestation", |attestation, processor| {
                    processor.apply(&UnboundedAttestation(attestation))
                }),
            "attester_slashing" => input.apply::<deneb::AttesterSlashing<P>>("attester_slashing"),
            "proposer_slashing" => input.apply::<deneb::ProposerSlashing>("proposer_slashing"),
            "deposit" => input.apply_with::<deneb::Deposit>("deposit", |deposit, processor| {
                processor.apply(&ParticipantDeposit(deposit))
            }),
            "voluntary_exit" => input
                .apply_with::<deneb::SignedVoluntaryExit>("voluntary_exit", |exit, processor| {
                    processor.apply(&Exit(exit))
                }),
            "bls_to_execution_change" => {
                input.apply::<deneb::SignedBlsToExecutionChange>("address_change")
            }
            "block_header" => input
                .apply_with::<deneb::BeaconBlock<P>>("block", |block, processor| {
                    processor.apply(&block.header())
                }),
            "sync_aggregate" => input.apply::<deneb::SyncAggregate<P>>("sync_aggregate"),
            "withdrawals" => input.apply_with::<deneb::ExecutionPayload<P>>(
                "execution_payload",
                |payload, processor| processor.apply(&PayloadWithdrawals(&payload.withdrawals)),
            ),
            "execution_payload" => {
                let engine = KnownVerdict(input.execution_verdict()?);
                input.apply_with::<deneb::BeaconBlockBody<P>>("body", |body, processor| {
                    processor.apply(&PayloadExecution::new(body, &engine))
                })
            }
            other => Err(Failure(format!("unsupported operation {other} in deneb"))),
        }
    }
}
