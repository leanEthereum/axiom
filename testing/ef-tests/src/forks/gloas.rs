//! The vectors of Gloas, which enshrines proposer-builder separation.

use axiom_gossip::GossipValidator;
use axiom_kzg::Kzg;
use axiom_state_transition::{
    electra::block::Exit,
    fulu::block::QueuedDeposit,
    gloas::block::{CommittedWithdrawals, IncludedAttestation, ParentPayload},
};
use axiom_types::{
    ColumnIndex, ForkName, Preset, gloas,
    vote::{CommitteeVote, ConflictingVotes},
};

use super::{Capella, Fulu, SpecFork};
use crate::{Applied, Case, Failure, FieldNames, GossipMessage, OperationInput, Verdict};

/// The Gloas fork.
///
/// Containers its spec left unchanged are Fulu's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gloas;

impl SpecFork for Gloas {
    const FORK: ForkName = ForkName::Gloas;

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
        "latest_block_hash",
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
        "proposer_lookahead",
        "builders",
        "next_withdrawal_builder_index",
        "execution_payload_availability",
        "builder_pending_payments",
        "builder_pending_withdrawals",
        "latest_execution_payload_bid",
        "payload_expected_withdrawals",
        "ptc_window",
    ]);

    type State<P: Preset> = gloas::BeaconState<P>;

    type SignedBeaconBlock<P: Preset> = gloas::SignedBeaconBlock<P>;

    type BeaconBlockBody<P: Preset> = gloas::BeaconBlockBody<P>;

    type Attestation<P: Preset> = gloas::Attestation<P>;

    type AttesterSlashing<P: Preset> = gloas::AttesterSlashing;

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
        let now = message.now_ms();
        Ok(match topic {
            "data_column_sidecar" => validator.gloas_data_column_sidecar(
                &message.decode::<gloas::DataColumnSidecar<P>>()?,
                now,
                message.subnet(),
                Kzg::mainnet(),
            ),
            "partial_data_column_sidecar" => validator.gloas_partial_data_column_sidecar(
                &message.decode::<gloas::PartialDataColumnSidecar<P>>()?,
                &message.decode_field::<gloas::PartialDataColumnGroupId>("group_id")?,
                ColumnIndex(message.number("column_index")),
                Kzg::mainnet(),
            ),
            "execution_payload" => validator.execution_payload_envelope(
                &message.decode::<gloas::SignedExecutionPayloadEnvelope<P>>()?,
            ),
            "payload_attestation_message" => validator.payload_attestation_message(
                &message.decode::<gloas::PayloadAttestationMessage>()?,
                now,
            ),
            "execution_payload_bid" => validator
                .execution_payload_bid(&message.decode::<gloas::SignedExecutionPayloadBid>()?, now),
            "proposer_preferences" => validator
                .proposer_preferences(&message.decode::<gloas::SignedProposerPreferences>()?, now),
            // Columns follow the bid now; the other topics are Capella's.
            _ => return Capella::gossip(topic, message, validator),
        })
    }

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

    fn operation<P: Preset>(
        handler: &str,
        input: &mut OperationInput<'_, '_, '_, gloas::BeaconState<P>>,
    ) -> Applied {
        match handler {
            "attestation" => {
                let parent_slot = input.parent_slot()?;
                input.apply_with::<gloas::Attestation<P>>(
                    "attestation",
                    |attestation, processor| {
                        processor.apply(&IncludedAttestation::new(attestation, parent_slot))
                    },
                )
            }
            "attester_slashing" => input.apply::<gloas::AttesterSlashing>("attester_slashing"),
            "proposer_slashing" => input.apply::<gloas::ProposerSlashing>("proposer_slashing"),
            "voluntary_exit" | "voluntary_exit_churn" => input
                .apply_with::<gloas::SignedVoluntaryExit>("voluntary_exit", |exit, processor| {
                    processor.apply(&Exit(exit))
                }),
            "bls_to_execution_change" => {
                input.apply::<gloas::SignedBlsToExecutionChange>("address_change")
            }
            "deposit_request" => input
                .apply_with::<gloas::DepositRequest>("deposit_request", |request, processor| {
                    processor.apply(&QueuedDeposit(request))
                }),
            "withdrawal_request" => input.apply::<gloas::WithdrawalRequest>("withdrawal_request"),
            "consolidation_request" => {
                input.apply::<gloas::ConsolidationRequest>("consolidation_request")
            }
            "builder_deposit_request" => {
                input.apply::<gloas::BuilderDepositRequest>("builder_deposit_request")
            }
            "builder_exit_request" => {
                input.apply::<gloas::BuilderExitRequest>("builder_exit_request")
            }
            "block_header" => input
                .apply_with::<gloas::BeaconBlock<P>>("block", |block, processor| {
                    processor.apply(&block.header())
                }),
            "sync_aggregate" => input.apply::<gloas::SyncAggregate<P>>("sync_aggregate"),
            // Gloas withdrawals read only the state, so the case has no input file.
            "withdrawals" => {
                input.apply_state_step(|processor| processor.apply(&CommittedWithdrawals))
            }
            "execution_payload_bid" => {
                input.apply::<gloas::SignedExecutionPayloadBid>("execution_payload_bid")
            }
            "parent_execution_payload" => input
                .apply_with::<gloas::BeaconBlock<P>>("block", |block, processor| {
                    processor.apply(&ParentPayload::of(&block.body))
                }),
            "payload_attestation" => {
                input.apply::<gloas::PayloadAttestation<P>>("payload_attestation")
            }
            other => Err(Failure(format!("unsupported operation {other} in gloas"))),
        }
    }
}
