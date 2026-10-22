//! The Fulu gossip rules: Electra's, with the blob limit read from the schedule.
//!
//! Fulu adds the data column topics, whose rules sit with the validator.
//! See the Fulu p2p spec.

use axiom_state_transition::State;
use axiom_types::{
    BlsSignature, ChainConfig, Domain, Epoch, Hash32, Preset, combined, deneb,
    fulu::{
        AttesterSlashing, BeaconBlock, BeaconState, SignedAggregateAndProof, SignedBeaconBlock,
        SingleAttestation,
    },
};

use super::{
    GossipFork, Verdict, VoteIndex, VoteWindow,
    bellatrix::{ParentPayload, PayloadTimestamp},
    deneb::BlobLimit,
};
use crate::{ChainView, GossipError};

impl<P: Preset> GossipFork for BeaconState<P> {
    type SignedBeaconBlock = SignedBeaconBlock<P>;
    type SignedAggregateAndProof = SignedAggregateAndProof<P>;
    type SubnetAttestation = SingleAttestation;
    type AttesterSlashing = AttesterSlashing<P>;

    const VOTE_WINDOW: VoteWindow = VoteWindow::CurrentOrPreviousEpoch;
    const VOTE_INDEX: VoteIndex = VoteIndex::Zero;

    fn into_any_block(signed: SignedBeaconBlock<P>) -> combined::SignedBeaconBlock<P> {
        combined::SignedBeaconBlock::Fulu(signed)
    }

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
        // EIP-7892: the limit follows the blob schedule.
        let limit = config
            .blob_parameters(block.slot.epoch::<P>())
            .max_blobs_per_block;
        BlobLimit(limit).check(block.body.blob_kzg_commitments.len())
    }
}
