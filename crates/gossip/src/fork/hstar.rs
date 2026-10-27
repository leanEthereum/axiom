//! The Hstar gossip rules: Gloas's, with key registrations among the block's operations.
//!
//! See the gossip section of EIP-8450.

use axiom_state_transition::State;
use axiom_types::{
    BlsSignature, ChainConfig, Domain, Epoch, Hash32, Preset, combined, deneb,
    gloas::{AttesterSlashing, ExecutionPayloadBid, SignedAggregateAndProof, SingleAttestation},
    hstar::{BeaconBlock, BeaconBlockBody, BeaconState, ExecutionRequests, SignedBeaconBlock},
};

use super::{
    GossipFork, Verdict, VoteIndex, VoteWindow,
    deneb::BlobLimit,
    gloas::{Bounded, ParentPayload},
};
use crate::{ChainView, Detail, GossipError};

impl<P: Preset> GossipFork for BeaconState<P> {
    type SignedBeaconBlock = SignedBeaconBlock<P>;
    type SignedAggregateAndProof = SignedAggregateAndProof<P>;
    type SubnetAttestation = SingleAttestation;
    type AttesterSlashing = AttesterSlashing;

    const VOTE_WINDOW: VoteWindow = VoteWindow::CurrentOrPreviousEpoch;
    const VOTE_INDEX: VoteIndex = VoteIndex::PayloadPresence;

    fn into_any_block(signed: SignedBeaconBlock<P>) -> combined::SignedBeaconBlock<P> {
        combined::SignedBeaconBlock::Hstar(signed)
    }

    fn split_block(signed: &SignedBeaconBlock<P>) -> (&BeaconBlock<P>, &BlsSignature) {
        (&signed.message, &signed.signature)
    }

    fn execution_block_hash(block: &BeaconBlock<P>) -> Hash32 {
        // The block commits to the payload its builder promised, which arrives later.
        block.body.signed_execution_payload_bid.message.block_hash
    }

    fn payload_bid(block: &BeaconBlock<P>) -> Option<&ExecutionPayloadBid> {
        Some(&block.body.signed_execution_payload_bid.message)
    }

    fn exit_domain(state: &combined::BeaconState<P>, config: &ChainConfig, epoch: Epoch) -> Domain {
        deneb::BeaconState::<P>::exit_domain(state, config, epoch)
    }

    fn check_execution(
        view: &ChainView<'_, P>,
        _head: &State<P>,
        block: &BeaconBlock<P>,
    ) -> Verdict {
        // A block that builds on its parent's payload needs that payload verified.
        if ParentPayload::of(view, block.parent_root, Self::payload_bid(block)).is_full()
            && !view.is_payload_verified(&block.parent_root)
        {
            return Err(GossipError::ignore("parent payload is not verified")
                .with(Detail::Block(block.parent_root)));
        }
        Ok(())
    }

    fn check_body(config: &ChainConfig, block: &BeaconBlock<P>) -> Verdict {
        OperationLimits(&block.body).check()?;
        ExecutionRequestLimits(&block.body.parent_execution_requests).check::<P>()?;
        let bid = &block.body.signed_execution_payload_bid.message;
        let limit = config
            .blob_parameters(block.slot.epoch::<P>())
            .max_blobs_per_block;
        BlobLimit(limit).check(bid.blob_kzg_commitments.len())?;
        if bid.parent_block_root != block.parent_root {
            return Err(
                GossipError::reject("bid's parent does not equal block's parent")
                    .with(Detail::Block(bid.parent_block_root)),
            );
        }
        Ok(())
    }

    fn check_parent_state(
        view: &ChainView<'_, P>,
        block: &BeaconBlock<P>,
        parent_state: &State<P>,
    ) -> Verdict {
        if ParentPayload::of(view, block.parent_root, Self::payload_bid(block)).is_full() {
            return Ok(());
        }
        // A block on an empty parent builds on the execution head the parent's state recorded.
        let bid = &block.body.signed_execution_payload_bid.message;
        if parent_state.beacon().latest_execution_block_hash() != Some(bid.parent_block_hash) {
            return Err(
                GossipError::reject("bid does not build on the parent's execution head")
                    .with(Detail::Block(block.parent_root)),
            );
        }
        Ok(())
    }
}

/// An Hstar block body, whose operation lists the type leaves unbounded.
#[derive(Clone, Copy, Debug)]
struct OperationLimits<'a, P: Preset>(&'a BeaconBlockBody<P>);

impl<P: Preset> OperationLimits<'_, P> {
    /// Rejects a body with an operation list above its limit, or with any deposit.
    ///
    /// See `verify_block_body_operation_limits` in the Gloas p2p spec, and EIP-8450's limit.
    fn check(self) -> Verdict {
        let body = self.0;
        let lists = [
            (
                body.proposer_slashings.len(),
                P::MAX_PROPOSER_SLASHINGS,
                "too many proposer slashings",
            ),
            (
                body.attester_slashings.len(),
                P::MAX_ATTESTER_SLASHINGS_ELECTRA,
                "too many attester slashings",
            ),
            (
                body.attestations.len(),
                P::MAX_ATTESTATIONS_ELECTRA,
                "too many attestations",
            ),
            // Deposits come through execution requests since Electra, so the list stays empty.
            (body.deposits.len(), 0, "block must not contain deposits"),
            (
                body.voluntary_exits.len(),
                P::MAX_VOLUNTARY_EXITS,
                "too many voluntary exits",
            ),
            (
                body.bls_to_execution_changes.len(),
                P::MAX_BLS_TO_EXECUTION_CHANGES,
                "too many bls to execution changes",
            ),
            (
                body.payload_attestations.len(),
                P::MAX_PAYLOAD_ATTESTATIONS,
                "too many payload attestations",
            ),
            (
                body.pq_key_registrations.len(),
                P::MAX_PQ_KEY_REGISTRATIONS,
                "too many key registrations",
            ),
        ];
        lists
            .into_iter()
            .try_for_each(|(count, limit, reason)| Bounded::new(count, limit, reason).check())
    }
}

/// Hstar's execution requests, whose lists the type leaves unbounded.
#[derive(Clone, Copy, Debug)]
struct ExecutionRequestLimits<'a>(&'a ExecutionRequests);

impl ExecutionRequestLimits<'_> {
    /// Rejects requests with a list above its limit.
    ///
    /// See `verify_execution_requests_limits` in the Gloas p2p spec, and EIP-8450's limit.
    fn check<P: Preset>(self) -> Verdict {
        let requests = self.0;
        let lists = [
            (
                requests.withdrawals.len(),
                P::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
                "too many withdrawal requests",
            ),
            (
                requests.consolidations.len(),
                P::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
                "too many consolidation requests",
            ),
            (
                requests.builder_deposits.len(),
                P::MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
                "too many builder deposit requests",
            ),
            (
                requests.builder_exits.len(),
                P::MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD,
                "too many builder exit requests",
            ),
            (
                requests.pq_key_authorizations.len(),
                P::MAX_PQ_KEY_AUTHORIZATION_REQUESTS_PER_PAYLOAD,
                "too many key authorization requests",
            ),
        ];
        lists
            .into_iter()
            .try_for_each(|(count, limit, reason)| Bounded::new(count, limit, reason).check())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, hstar::SignedPqKeyRegistration};

    use super::*;

    #[test]
    fn a_ninth_registration_is_rejected() {
        // The limit is 8 per block; the body carries 9.
        let mut body = BeaconBlockBody::<Minimal>::default();
        for _ in 0..9 {
            body.pq_key_registrations
                .push(SignedPqKeyRegistration::default());
        }

        let error = OperationLimits(&body).check().unwrap_err();

        assert_eq!(
            error,
            GossipError::reject("too many key registrations")
                .with(Detail::Bound { value: 9, bound: 8 })
        );
    }
}
