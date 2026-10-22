//! The Capella gossip rules: every block carries a payload, and withdrawal credentials change.
//!
//! See the Capella p2p spec.

use axiom_state_transition::State;
use axiom_types::{
    BlsSignature, Hash32, Preset,
    capella::{
        Attestation, AttesterSlashing, BeaconBlock, BeaconState, SignedAggregateAndProof,
        SignedBeaconBlock,
    },
};

use super::{
    GossipFork, Verdict, VoteIndex, VoteWindow,
    bellatrix::{ParentPayload, PayloadTimestamp},
};
use crate::{ChainView, GossipError};

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

    fn execution_block_hash(block: &BeaconBlock<P>) -> Hash32 {
        block.body.execution_payload.block_hash
    }

    fn failed_parent(view: &ChainView<'_, P>, block: &BeaconBlock<P>) -> GossipError {
        // The merge is behind every Capella block, so the payload status alone decides.
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
}
