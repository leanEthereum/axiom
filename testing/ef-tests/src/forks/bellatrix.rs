//! The vectors of Bellatrix, the merge with the execution layer.

use axiom_types::{ForkName, Preset, bellatrix};

use super::{Altair, SpecFork};
use crate::{Case, Failure};

/// The Bellatrix fork.
///
/// Containers its spec left unchanged are Altair's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bellatrix;

impl SpecFork for Bellatrix {
    const FORK: ForkName = ForkName::Bellatrix;

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
