//! The vectors of Electra, which adds larger validators and execution requests.

use axiom_types::{ForkName, Preset, electra};

use super::{Deneb, SpecFork};
use crate::{Case, Failure, FieldNames};

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
