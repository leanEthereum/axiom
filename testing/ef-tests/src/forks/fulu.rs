//! The vectors of Fulu, which adds peer data availability sampling.

use axiom_state_transition::{
    KnownVerdict,
    electra::block::{Exit, PayloadWithdrawals},
    fulu::block::{PayloadExecution, QueuedDeposit},
};
use axiom_types::{ForkName, Preset, fulu};

use super::{Electra, SpecFork};
use crate::{Applied, Case, Failure, FieldNames, OperationInput};

/// The Fulu fork.
///
/// Containers its spec left unchanged are Electra's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fulu;

impl SpecFork for Fulu {
    const FORK: ForkName = ForkName::Fulu;

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
        "proposer_lookahead",
    ]);

    type State<P: Preset> = fulu::BeaconState<P>;

    type SignedBeaconBlock<P: Preset> = fulu::SignedBeaconBlock<P>;

    fn ssz_static<P: Preset>(container: &str, case: &Case) -> Result<(), Failure> {
        match container {
            "BeaconState" => case.round_trip::<fulu::BeaconState<P>>(),
            "DataColumnSidecar" => case.round_trip::<fulu::DataColumnSidecar<P>>(),
            "DataColumnsByRootIdentifier" => {
                case.round_trip::<fulu::DataColumnsByRootIdentifier<P>>()
            }
            "MatrixEntry" => case.round_trip::<fulu::MatrixEntry<P>>(),
            "PartialDataColumnGroupID" => case.round_trip::<fulu::PartialDataColumnGroupId>(),
            "PartialDataColumnHeader" => case.round_trip::<fulu::PartialDataColumnHeader<P>>(),
            "PartialDataColumnPartsMetadata" => {
                case.round_trip::<fulu::PartialDataColumnPartsMetadata<P>>()
            }
            "PartialDataColumnSidecar" => case.round_trip::<fulu::PartialDataColumnSidecar<P>>(),
            _ => Electra::ssz_static::<P>(container, case),
        }
    }

    fn operation<P: Preset>(
        handler: &str,
        input: &mut OperationInput<'_, '_, '_, fulu::BeaconState<P>>,
    ) -> Applied {
        match handler {
            "attestation" => input.apply::<fulu::Attestation<P>>("attestation"),
            "attester_slashing" => input.apply::<fulu::AttesterSlashing<P>>("attester_slashing"),
            "proposer_slashing" => input.apply::<fulu::ProposerSlashing>("proposer_slashing"),
            "voluntary_exit" => input
                .apply_with::<fulu::SignedVoluntaryExit>("voluntary_exit", |exit, processor| {
                    processor.apply(&Exit(exit))
                }),
            "bls_to_execution_change" => {
                input.apply::<fulu::SignedBlsToExecutionChange>("address_change")
            }
            "deposit_request" => input
                .apply_with::<fulu::DepositRequest>("deposit_request", |request, processor| {
                    processor.apply(&QueuedDeposit(request))
                }),
            "withdrawal_request" => input.apply::<fulu::WithdrawalRequest>("withdrawal_request"),
            "consolidation_request" => {
                input.apply::<fulu::ConsolidationRequest>("consolidation_request")
            }
            "block_header" => input
                .apply_with::<fulu::BeaconBlock<P>>("block", |block, processor| {
                    processor.apply(&block.header())
                }),
            "sync_aggregate" => input.apply::<fulu::SyncAggregate<P>>("sync_aggregate"),
            "withdrawals" => input.apply_with::<fulu::ExecutionPayload<P>>(
                "execution_payload",
                |payload, processor| processor.apply(&PayloadWithdrawals(&payload.withdrawals)),
            ),
            "execution_payload" => {
                let engine = KnownVerdict(input.execution_verdict()?);
                input.apply_with::<fulu::BeaconBlockBody<P>>("body", |body, processor| {
                    processor.apply(&PayloadExecution::new(body, &engine))
                })
            }
            other => Err(Failure(format!("unsupported operation {other} in fulu"))),
        }
    }
}
