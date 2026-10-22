//! The vectors of Deneb, which adds blobs.

use axiom_types::{ForkName, Preset, deneb};

use super::{Capella, SpecFork};
use crate::{Case, Failure, FieldNames};

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
}
