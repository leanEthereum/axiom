//! The vectors of Electra, which adds larger validators and execution requests.

use axiom_gossip::{BlobSubnets, GossipValidator};
use axiom_kzg::Kzg;
use axiom_state_transition::{
    KnownVerdict,
    electra::block::{BridgeDeposit, Exit, PayloadExecution, PayloadWithdrawals, RequestedDeposit},
};
use axiom_types::{
    ForkName, Preset, electra,
    vote::{CommitteeVote, ConflictingVotes},
};

use super::{Capella, Deneb, SpecFork};
use crate::{Applied, Case, Failure, FieldNames, GossipMessage, OperationInput, Verdict};

/// The Electra fork.
///
/// Containers its spec left unchanged are Deneb's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Electra;

impl SpecFork for Electra {
    const FORK: ForkName = ForkName::Electra;

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
        "deposit_requests_start_index",
        "deposit_balance_to_consume",
        "exit_balance_to_consume",
        "earliest_exit_epoch",
        "consolidation_balance_to_consume",
        "earliest_consolidation_epoch",
        "pending_deposits",
        "pending_partial_withdrawals",
        "pending_consolidations",
    ]);

    type State<P: Preset> = electra::BeaconState<P>;

    type SignedBeaconBlock<P: Preset> = electra::SignedBeaconBlock<P>;

    type BeaconBlockBody<P: Preset> = electra::BeaconBlockBody<P>;

    type Attestation<P: Preset> = electra::Attestation<P>;

    type AttesterSlashing<P: Preset> = electra::AttesterSlashing<P>;

    fn committee_vote<P: Preset>(attestation: &Self::Attestation<P>) -> CommitteeVote {
        attestation.committee_vote()
    }

    fn conflicting_votes<P: Preset>(slashing: &Self::AttesterSlashing<P>) -> ConflictingVotes {
        slashing.conflicting_votes()
    }

    fn gossip<P: Preset>(
        topic: &str,
        message: &GossipMessage<'_>,
        validator: &mut GossipValidator<'_, '_, P>,
    ) -> Result<Verdict, Failure> {
        match topic {
            "blob_sidecar" => {
                let limits = BlobSubnets::electra(validator.config());
                Ok(validator.blob_sidecar(
                    &message.decode::<electra::BlobSidecar<P>>()?,
                    message.now_ms(),
                    message.subnet(),
                    limits,
                    Kzg::mainnet(),
                ))
            }
            // Electra kept the remaining topics of Capella.
            _ => Capella::gossip(topic, message, validator),
        }
    }

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

    fn operation<P: Preset>(
        handler: &str,
        input: &mut OperationInput<'_, '_, '_, electra::BeaconState<P>>,
    ) -> Applied {
        match handler {
            "attestation" => input.apply::<electra::Attestation<P>>("attestation"),
            "attester_slashing" => input.apply::<electra::AttesterSlashing<P>>("attester_slashing"),
            "proposer_slashing" => input.apply::<electra::ProposerSlashing>("proposer_slashing"),
            "deposit" => input.apply_with::<electra::Deposit>("deposit", |deposit, processor| {
                processor.apply(&BridgeDeposit(deposit))
            }),
            "voluntary_exit" => input
                .apply_with::<electra::SignedVoluntaryExit>("voluntary_exit", |exit, processor| {
                    processor.apply(&Exit(exit))
                }),
            "bls_to_execution_change" => {
                input.apply::<electra::SignedBlsToExecutionChange>("address_change")
            }
            "deposit_request" => input
                .apply_with::<electra::DepositRequest>("deposit_request", |request, processor| {
                    processor.apply(&RequestedDeposit(request))
                }),
            "withdrawal_request" => input.apply::<electra::WithdrawalRequest>("withdrawal_request"),
            "consolidation_request" => {
                input.apply::<electra::ConsolidationRequest>("consolidation_request")
            }
            "block_header" => input
                .apply_with::<electra::BeaconBlock<P>>("block", |block, processor| {
                    processor.apply(&block.header())
                }),
            "sync_aggregate" => input.apply::<electra::SyncAggregate<P>>("sync_aggregate"),
            "withdrawals" => input.apply_with::<electra::ExecutionPayload<P>>(
                "execution_payload",
                |payload, processor| {
                    processor.apply(&PayloadWithdrawals::listed(&payload.withdrawals))
                },
            ),
            "execution_payload" => {
                let engine = KnownVerdict(input.execution_verdict()?);
                input.apply_with::<electra::BeaconBlockBody<P>>("body", |body, processor| {
                    processor.apply(&PayloadExecution::new(body, &engine))
                })
            }
            other => Err(Failure(format!("unsupported operation {other} in electra"))),
        }
    }
}
