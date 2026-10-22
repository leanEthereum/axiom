//! The vectors of Deneb, which adds blobs.

use axiom_types::{ForkName, Preset, deneb};

use super::{Capella, SpecFork};
use crate::{Case, Failure};

/// The Deneb fork.
///
/// Containers its spec left unchanged are Capella's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Deneb;

impl SpecFork for Deneb {
    const FORK: ForkName = ForkName::Deneb;

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
