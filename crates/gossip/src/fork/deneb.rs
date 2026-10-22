//! The Deneb gossip rules: blobs, late votes, and exits signed for good.
//!
//! See the Deneb p2p spec.

use axiom_state_transition::State;
use axiom_types::{
    BlsSignature, ChainConfig, Domain, Epoch, Hash32, Preset,
    accessors::CoreState,
    combined,
    constants::DOMAIN_VOLUNTARY_EXIT,
    deneb::{
        Attestation, AttesterSlashing, BeaconBlock, BeaconState, SignedAggregateAndProof,
        SignedBeaconBlock,
    },
};

use super::{
    GossipFork, Verdict, VoteIndex, VoteWindow,
    bellatrix::{ParentPayload, PayloadTimestamp},
};
use crate::{ChainView, Detail, GossipError};

impl<P: Preset> GossipFork for BeaconState<P> {
    type SignedBeaconBlock = SignedBeaconBlock<P>;
    type SignedAggregateAndProof = SignedAggregateAndProof<P>;
    type SubnetAttestation = Attestation<P>;
    type AttesterSlashing = AttesterSlashing<P>;

    const VOTE_WINDOW: VoteWindow = VoteWindow::CurrentOrPreviousEpoch;
    const VOTE_INDEX: VoteIndex = VoteIndex::Committee;

    fn split_block(signed: &SignedBeaconBlock<P>) -> (&BeaconBlock<P>, &BlsSignature) {
        (&signed.message, &signed.signature)
    }

    fn execution_block_hash(block: &BeaconBlock<P>) -> Hash32 {
        block.body.execution_payload.block_hash
    }

    fn exit_domain(
        state: &combined::BeaconState<P>,
        config: &ChainConfig,
        _epoch: Epoch,
    ) -> Domain {
        // EIP-7044: exits are signed in the Capella domain, so they stay valid across forks.
        Domain::compute(
            DOMAIN_VOLUNTARY_EXIT,
            config.capella_fork_version,
            state.genesis_validators_root(),
        )
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
        BlobLimit(config.max_blobs_per_block).check(block.body.blob_kzg_commitments.len())
    }
}

/// The most blobs a block may commit to.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BlobLimit(pub(crate) u64);

impl BlobLimit {
    /// Rejects a commitment count above the limit.
    pub(crate) const fn check(self, count: usize) -> Verdict {
        let count = count as u64;
        if count > self.0 {
            return Err(
                GossipError::reject("too many blob kzg commitments").with(Detail::Bound {
                    value: count,
                    bound: self.0,
                }),
            );
        }
        Ok(())
    }
}
