//! The vectors of Altair, which adds sync committees and participation flags.

use axiom_gossip::GossipValidator;
use axiom_state_transition::altair::block::{FlaggedAttestation, ParticipantDeposit};
use axiom_types::{
    ForkName, Preset, altair, phase0,
    vote::{CommitteeVote, ConflictingVotes},
};

use super::{Phase0, SpecFork};
use crate::{Applied, Case, Failure, FieldNames, GossipMessage, OperationInput, Verdict};

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

    type BeaconBlockBody<P: Preset> = altair::BeaconBlockBody<P>;

    type Attestation<P: Preset> = phase0::Attestation<P>;

    type AttesterSlashing<P: Preset> = phase0::AttesterSlashing<P>;

    fn committee_vote<P: Preset>(attestation: &Self::Attestation<P>) -> CommitteeVote {
        attestation.committee_vote()
    }

    fn conflicting_votes<P: Preset>(slashing: &Self::AttesterSlashing<P>) -> ConflictingVotes {
        slashing.conflicting_votes()
    }

    fn gossip<P: Preset>(
        topic: &str,
        message: &GossipMessage<'_>,
        validator: &mut GossipValidator<'_, '_, P>,
    ) -> Result<Verdict, Failure> {
        let now = message.now_ms();
        Ok(match topic {
            "sync_committee_contribution_and_proof" => validator.sync_contribution(
                &message.decode::<altair::SignedContributionAndProof<P>>()?,
                now,
            ),
            "sync_committee" => validator.sync_committee_message(
                &message.decode::<altair::SyncCommitteeMessage>()?,
                now,
                message.subnet(),
            ),
            other => {
                return Err(Failure(format!(
                    "unsupported gossip topic {other} in altair"
                )));
            }
        })
    }

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

    fn operation<P: Preset>(
        handler: &str,
        input: &mut OperationInput<'_, '_, '_, altair::BeaconState<P>>,
    ) -> Applied {
        match handler {
            "attestation" => input
                .apply_with::<altair::Attestation<P>>("attestation", |attestation, processor| {
                    processor.apply(&FlaggedAttestation(attestation))
                }),
            "attester_slashing" => input.apply::<altair::AttesterSlashing<P>>("attester_slashing"),
            "block_header" => input
                .apply_with::<altair::BeaconBlock<P>>("block", |block, processor| {
                    processor.apply(&block.header())
                }),
            "deposit" => input.apply_with::<altair::Deposit>("deposit", |deposit, processor| {
                processor.apply(&ParticipantDeposit(deposit))
            }),
            "proposer_slashing" => input.apply::<altair::ProposerSlashing>("proposer_slashing"),
            "sync_aggregate" => input.apply::<altair::SyncAggregate<P>>("sync_aggregate"),
            "voluntary_exit" => input.apply::<altair::SignedVoluntaryExit>("voluntary_exit"),
            other => Err(Failure(format!("unsupported operation {other} in altair"))),
        }
    }
}
