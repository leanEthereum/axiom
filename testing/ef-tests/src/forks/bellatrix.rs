//! The vectors of Bellatrix, the merge with the execution layer.

use axiom_types::{ForkName, Preset, bellatrix};

use super::{Altair, SpecFork};
use crate::{Case, Failure, FieldNames};

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
}
