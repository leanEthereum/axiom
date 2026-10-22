//! The vectors of Altair, which adds sync committees and participation flags.

use axiom_types::{ForkName, Preset, altair};

use super::{Phase0, SpecFork};
use crate::{Case, Failure, FieldNames};

/// The Altair fork.
///
/// Containers its spec left unchanged are phase0's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Altair;

impl SpecFork for Altair {
    const FORK: ForkName = ForkName::Altair;

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
    ]);

    type State<P: Preset> = altair::BeaconState<P>;

    type SignedBeaconBlock<P: Preset> = altair::SignedBeaconBlock<P>;

    fn ssz_static<P: Preset>(container: &str, case: &Case) -> Result<(), Failure> {
        match container {
            "BeaconBlock" => case.round_trip::<altair::BeaconBlock<P>>(),
            "BeaconBlockBody" => case.round_trip::<altair::BeaconBlockBody<P>>(),
            "BeaconState" => case.round_trip::<altair::BeaconState<P>>(),
            "ContributionAndProof" => case.round_trip::<altair::ContributionAndProof<P>>(),
            "LightClientBootstrap" => case.round_trip::<altair::LightClientBootstrap<P>>(),
            "LightClientFinalityUpdate" => {
                case.round_trip::<altair::LightClientFinalityUpdate<P>>()
            }
            "LightClientHeader" => case.round_trip::<altair::LightClientHeader>(),
            "LightClientOptimisticUpdate" => {
                case.round_trip::<altair::LightClientOptimisticUpdate<P>>()
            }
            "LightClientUpdate" => case.round_trip::<altair::LightClientUpdate<P>>(),
            "SignedBeaconBlock" => case.round_trip::<altair::SignedBeaconBlock<P>>(),
            "SignedContributionAndProof" => {
                case.round_trip::<altair::SignedContributionAndProof<P>>()
            }
            "SyncAggregate" => case.round_trip::<altair::SyncAggregate<P>>(),
            "SyncAggregatorSelectionData" => {
                case.round_trip::<altair::SyncAggregatorSelectionData>()
            }
            "SyncCommittee" => case.round_trip::<altair::SyncCommittee<P>>(),
            "SyncCommitteeContribution" => {
                case.round_trip::<altair::SyncCommitteeContribution<P>>()
            }
            "SyncCommitteeMessage" => case.round_trip::<altair::SyncCommitteeMessage>(),
            _ => Phase0::ssz_static::<P>(container, case),
        }
    }
}
