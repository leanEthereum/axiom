//! The vectors of Capella, which adds withdrawals.

use axiom_types::{ForkName, Preset, capella};

use super::{Bellatrix, SpecFork};
use crate::{Case, Failure};

/// The Capella fork.
///
/// Containers its spec left unchanged are Bellatrix's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capella;

impl SpecFork for Capella {
    const FORK: ForkName = ForkName::Capella;

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
