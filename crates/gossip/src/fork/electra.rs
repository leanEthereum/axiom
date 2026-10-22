//! The Electra gossip rules: committees named outside the vote, and more blobs.
//!
//! See the Electra p2p spec.

use axiom_state_transition::State;
use axiom_types::{
    BlsSignature, ChainConfig, CommitteeIndex, Domain, Epoch, Hash32, Preset, ValidatorIndex,
    combined, deneb,
    electra::{
        AggregateAndProof, Attestation, AttestationData, AttesterSlashing, BeaconBlock,
        BeaconState, SignedAggregateAndProof, SignedBeaconBlock, SingleAttestation,
    },
};

use super::{
    GossipFork, Verdict, VoteIndex, VoteWindow,
    bellatrix::{ParentPayload, PayloadTimestamp},
    deneb::BlobLimit,
};
use crate::{
    ChainView, Detail, GossipError,
    vote::{Aggregate, IndexedVote, SignedAggregate, SlashingEvidence, SubnetVote},
};

impl<P: Preset> GossipFork for BeaconState<P> {
    type SignedBeaconBlock = SignedBeaconBlock<P>;
    type SignedAggregateAndProof = SignedAggregateAndProof<P>;
    type SubnetAttestation = SingleAttestation;
    type AttesterSlashing = AttesterSlashing<P>;

    const VOTE_WINDOW: VoteWindow = VoteWindow::CurrentOrPreviousEpoch;
    const VOTE_INDEX: VoteIndex = VoteIndex::Zero;

    fn split_block(signed: &SignedBeaconBlock<P>) -> (&BeaconBlock<P>, &BlsSignature) {
        (&signed.message, &signed.signature)
    }

    fn execution_block_hash(block: &BeaconBlock<P>) -> Hash32 {
        block.body.execution_payload.block_hash
    }

    fn exit_domain(state: &combined::BeaconState<P>, config: &ChainConfig, epoch: Epoch) -> Domain {
        deneb::BeaconState::<P>::exit_domain(state, config, epoch)
    }

    fn failed_parent(view: &ChainView<'_, P>, block: &BeaconBlock<P>) -> GossipError {
        ParentPayload::of(view, block.parent_root).failed()
    }

    fn check_execution(
        view: &ChainView<'_, P>,
        head: &State<P>,
        block: &BeaconBlock<P>,
    ) -> Verdict {
        ParentPayload::of(view, block.parent_root).not_invalid()?;
        PayloadTimestamp::new(block.body.execution_payload.timestamp, block.slot)
            .check(view.config(), head)
    }

    fn check_body(config: &ChainConfig, block: &BeaconBlock<P>) -> Verdict {
        // EIP-7691 raised the limit.
        BlobLimit(config.max_blobs_per_block_electra).check(block.body.blob_kzg_commitments.len())
    }
}

impl<P: Preset> Aggregate for Attestation<P> {
    fn data(&self) -> &AttestationData {
        &self.data
    }

    fn bits(&self) -> Vec<bool> {
        self.aggregation_bits.iter().collect()
    }

    fn signature(&self) -> &BlsSignature {
        &self.signature
    }

    fn committee(&self) -> Result<CommitteeIndex, GossipError> {
        OneCommittee::of(self.committee_indices())
    }
}

/// The committees an aggregate's committee bits name, of which there must be exactly one.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OneCommittee;

impl OneCommittee {
    /// The single committee named.
    ///
    /// # Errors
    ///
    /// Rejects bits naming no committee or several.
    pub(crate) fn of(
        committees: impl Iterator<Item = CommitteeIndex>,
    ) -> Result<CommitteeIndex, GossipError> {
        let committees: Vec<CommitteeIndex> = committees.collect();
        let [index] = committees[..] else {
            return Err(GossipError::reject(
                "aggregate committee bits must specify exactly one committee",
            )
            .with(Detail::Mismatch {
                actual: committees.len() as u64,
                expected: 1,
            }));
        };
        Ok(index)
    }
}

impl<P: Preset> SignedAggregate for SignedAggregateAndProof<P> {
    type Message = AggregateAndProof<P>;
    type Aggregate = Attestation<P>;

    fn message(&self) -> &AggregateAndProof<P> {
        &self.message
    }

    fn aggregate(&self) -> &Attestation<P> {
        &self.message.aggregate
    }

    fn aggregator_index(&self) -> ValidatorIndex {
        self.message.aggregator_index
    }

    fn selection_proof(&self) -> &BlsSignature {
        &self.message.selection_proof
    }

    fn signature(&self) -> &BlsSignature {
        &self.signature
    }
}

impl SubnetVote for SingleAttestation {
    fn data(&self) -> &AttestationData {
        &self.data
    }

    fn signature(&self) -> &BlsSignature {
        &self.signature
    }

    fn committee_index(&self) -> CommitteeIndex {
        self.committee_index
    }

    fn attester(&self, committee: &[ValidatorIndex]) -> Result<ValidatorIndex, GossipError> {
        if !committee.contains(&self.attester_index) {
            return Err(
                GossipError::reject("attester is not a member of the committee")
                    .with(Detail::Validator(self.attester_index)),
            );
        }
        Ok(self.attester_index)
    }
}

impl<P: Preset> SlashingEvidence for AttesterSlashing<P> {
    fn votes(&self) -> [IndexedVote<'_>; 2] {
        [&self.attestation_1, &self.attestation_2].map(|attestation| IndexedVote {
            indices: &attestation.attesting_indices,
            data: &attestation.data,
            signature: &attestation.signature,
        })
    }
}
