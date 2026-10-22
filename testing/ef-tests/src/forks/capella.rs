//! The vectors of Capella, which adds withdrawals.

use axiom_types::{ForkName, Preset, capella};

use super::{Bellatrix, SpecFork};
use crate::{Case, Failure, FieldNames};

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
}
