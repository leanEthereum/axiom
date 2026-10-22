//! The vectors of Fulu, which adds peer data availability sampling.

use axiom_types::{ForkName, Preset, fulu};

use super::{Electra, SpecFork};
use crate::{Case, Failure};

/// The Fulu fork.
///
/// Containers its spec left unchanged are Electra's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fulu;

impl SpecFork for Fulu {
    const FORK: ForkName = ForkName::Fulu;

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
}
