//! The phase0 gossip rules, which every later fork amends.
//!
//! See the phase0 p2p spec.

use axiom_types::{
    BlsSignature, CommitteeIndex, Hash32, Preset, ValidatorIndex,
    phase0::{
        AggregateAndProof, Attestation, AttestationData, AttesterSlashing, BeaconBlock,
        BeaconState, SignedAggregateAndProof, SignedBeaconBlock,
    },
};

use super::{GossipFork, VoteIndex, VoteWindow};
use crate::{
    Detail, GossipError,
    vote::{Aggregate, IndexedVote, SignedAggregate, SlashingEvidence, SubnetVote},
};

impl<P: Preset> GossipFork for BeaconState<P> {
    type SignedBeaconBlock = SignedBeaconBlock<P>;
    type SignedAggregateAndProof = SignedAggregateAndProof<P>;
    type SubnetAttestation = Attestation<P>;
    type AttesterSlashing = AttesterSlashing<P>;

    const VOTE_WINDOW: VoteWindow = VoteWindow::SlotRange;
    const VOTE_INDEX: VoteIndex = VoteIndex::Committee;

    fn split_block(signed: &SignedBeaconBlock<P>) -> (&BeaconBlock<P>, &BlsSignature) {
        (&signed.message, &signed.signature)
    }

    fn execution_block_hash(_block: &BeaconBlock<P>) -> Hash32 {
        Hash32::default()
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
        // Before Electra the data names the committee.
        Ok(self.data.index)
    }
}

impl<P: Preset> SubnetVote for Attestation<P> {
    fn data(&self) -> &AttestationData {
        &self.data
    }

    fn signature(&self) -> &BlsSignature {
        &self.signature
    }

    fn committee_index(&self) -> CommitteeIndex {
        self.data.index
    }

    fn attester(&self, committee: &[ValidatorIndex]) -> Result<ValidatorIndex, GossipError> {
        let set = self.aggregation_bits.count_ones();
        if set != 1 {
            return Err(GossipError::reject("attestation is not unaggregated").with(
                Detail::Mismatch {
                    actual: set as u64,
                    expected: 1,
                },
            ));
        }
        let length = self.aggregation_bits.len();
        if length != committee.len() {
            return Err(GossipError::reject(
                "aggregation bits length does not match committee size",
            )
            .with(Detail::Mismatch {
                actual: length as u64,
                expected: committee.len() as u64,
            }));
        }
        // Invariant: exactly one bit is set, and the bits are as long as the committee.
        let position = self
            .aggregation_bits
            .iter()
            .position(|bit| bit)
            .unwrap_or_default();
        Ok(committee[position])
    }
}

impl<P: Preset> SignedAggregate for SignedAggregateAndProof<P> {
    type Message = AggregateAndProof<P>;
    type Aggregate = Attestation<P>;

    fn message(&self) -> &Self::Message {
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

impl<P: Preset> SlashingEvidence for AttesterSlashing<P> {
    fn votes(&self) -> [IndexedVote<'_>; 2] {
        [&self.attestation_1, &self.attestation_2].map(|attestation| IndexedVote {
            indices: &attestation.attesting_indices,
            data: &attestation.data,
            signature: &attestation.signature,
        })
    }
}
