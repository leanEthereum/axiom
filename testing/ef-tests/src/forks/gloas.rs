//! The vectors of Gloas, which enshrines proposer-builder separation.

use axiom_types::{ForkName, Preset, gloas};

use super::{Fulu, SpecFork};
use crate::{Case, Failure, FieldNames};

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
