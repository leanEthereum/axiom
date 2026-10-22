//! The Altair gossip rules: phase0's on the shared topics.
//!
//! Altair adds the sync committee topics, whose rules no later fork changed.
//! See the Altair p2p spec.

use axiom_types::{
    BlsSignature, Hash32, Preset,
    altair::{
        Attestation, AttesterSlashing, BeaconBlock, BeaconState, SignedAggregateAndProof,
        SignedBeaconBlock,
    },
};

use super::{GossipFork, VoteIndex, VoteWindow};

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
