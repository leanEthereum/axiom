//! The Gloas gossip rules: blocks carry a builder's bid, and votes say if the payload came.
//!
//! See the Gloas p2p spec, EIP-7732 and EIP-7688.

use axiom_state_transition::State;
use axiom_types::{
    BlsSignature, BuilderIndex, ChainConfig, CommitteeIndex, Domain, Epoch, Gwei, Hash32, Preset,
    Root, Slot, ValidatorIndex,
    accessors::BuilderState,
    combined, deneb,
    gloas::{
        AggregateAndProof, Attestation, AttestationData, AttesterSlashing, BeaconBlock,
        BeaconBlockBody, BeaconState, ExecutionPayloadBid, ExecutionRequests,
        SignedAggregateAndProof, SignedBeaconBlock, SingleAttestation,
    },
    vote::{CommitteeVote, ConflictingVotes},
};

use super::{GossipFork, Verdict, VoteIndex, VoteWindow, deneb::BlobLimit, electra::OneCommittee};
use crate::{
    ChainView, Detail, GossipError,
    vote::{Aggregate, IndexedVote, SignedAggregate, SlashingEvidence},
};

impl<P: Preset> GossipFork for BeaconState<P> {
    type SignedBeaconBlock = SignedBeaconBlock<P>;
    type SignedAggregateAndProof = SignedAggregateAndProof<P>;
    type SubnetAttestation = SingleAttestation;
    type AttesterSlashing = AttesterSlashing;

    const VOTE_WINDOW: VoteWindow = VoteWindow::CurrentOrPreviousEpoch;
    const VOTE_INDEX: VoteIndex = VoteIndex::PayloadPresence;

    fn into_any_block(signed: SignedBeaconBlock<P>) -> combined::SignedBeaconBlock<P> {
        combined::SignedBeaconBlock::Gloas(signed)
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

/// Whether a block builds on its parent's payload or on the parent alone.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ParentPayload {
    /// The payload the block's bid builds on.
    parent_block_hash: Hash32,
    /// The payload the parent's bid promised, when the parent is known.
    promised: Option<Hash32>,
}

impl ParentPayload {
    /// What a view knows of the parent payload a block's bid builds on.
    ///
    /// A block without a bid builds on no payload, so its parent never counts as full.
    pub(crate) fn of<P: Preset>(
        view: &ChainView<'_, P>,
        parent_root: Root,
        bid: Option<&ExecutionPayloadBid>,
    ) -> Self {
        Self {
            parent_block_hash: bid.map_or(Hash32::ZERO, |bid| bid.parent_block_hash),
            promised: bid.and_then(|_| {
                view.block(&parent_root)
                    .map(|parent| parent.execution_block_hash)
            }),
        }
    }

    /// Whether the block builds on the payload its parent promised.
    ///
    /// See `is_parent_node_full` in the Gloas fork choice spec.
    pub(crate) fn is_full(self) -> bool {
        self.promised == Some(self.parent_block_hash)
    }
}

/// A block body, whose operation lists the type leaves unbounded since EIP-7688.
#[derive(Clone, Copy, Debug)]
struct OperationLimits<'a, P: Preset>(&'a BeaconBlockBody<P>);

impl<P: Preset> OperationLimits<'_, P> {
    /// Rejects a body with an operation list above its limit, or with any deposit.
    ///
    /// See `verify_block_body_operation_limits` in the Gloas p2p spec.
    fn check(self) -> Verdict {
        let body = self.0;
        Bounded::new(
            body.proposer_slashings.len(),
            P::MAX_PROPOSER_SLASHINGS,
            "too many proposer slashings",
        )
        .check()?;
        Bounded::new(
            body.attester_slashings.len(),
            P::MAX_ATTESTER_SLASHINGS_ELECTRA,
            "too many attester slashings",
        )
        .check()?;
        Bounded::new(
            body.attestations.len(),
            P::MAX_ATTESTATIONS_ELECTRA,
            "too many attestations",
        )
        .check()?;
        // Deposits come through execution requests since Electra, so the list stays empty.
        Bounded::new(body.deposits.len(), 0, "block must not contain deposits").check()?;
        Bounded::new(
            body.voluntary_exits.len(),
            P::MAX_VOLUNTARY_EXITS,
            "too many voluntary exits",
        )
        .check()?;
        Bounded::new(
            body.bls_to_execution_changes.len(),
            P::MAX_BLS_TO_EXECUTION_CHANGES,
            "too many bls to execution changes",
        )
        .check()?;
        Bounded::new(
            body.payload_attestations.len(),
            P::MAX_PAYLOAD_ATTESTATIONS,
            "too many payload attestations",
        )
        .check()
    }
}

/// Execution requests, whose lists the type leaves unbounded since EIP-7688.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ExecutionRequestLimits<'a>(pub(crate) &'a ExecutionRequests);

impl ExecutionRequestLimits<'_> {
    /// Rejects requests with a list above its limit.
    ///
    /// See `verify_execution_requests_limits` in the Gloas p2p spec.
    pub(crate) fn check<P: Preset>(self) -> Verdict {
        let requests = self.0;
        Bounded::new(
            requests.withdrawals.len(),
            P::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
            "too many withdrawal requests",
        )
        .check()?;
        Bounded::new(
            requests.consolidations.len(),
            P::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
            "too many consolidation requests",
        )
        .check()?;
        Bounded::new(
            requests.builder_deposits.len(),
            P::MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
            "too many builder deposit requests",
        )
        .check()?;
        Bounded::new(
            requests.builder_exits.len(),
            P::MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD,
            "too many builder exit requests",
        )
        .check()
    }
}

/// A list's length, the most the spec allows, and the rule that limit belongs to.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Bounded {
    /// The list's length.
    count: u64,
    /// The most the spec allows.
    limit: u64,
    /// The rule, in the spec's wording.
    reason: &'static str,
}

impl Bounded {
    /// A length checked against a limit.
    pub(crate) const fn new(count: usize, limit: u64, reason: &'static str) -> Self {
        Self {
            count: count as u64,
            limit,
            reason,
        }
    }

    /// Rejects a length above the limit.
    pub(crate) const fn check(self) -> Verdict {
        if self.count > self.limit {
            return Err(GossipError::reject(self.reason).with(Detail::Bound {
                value: self.count,
                bound: self.limit,
            }));
        }
        Ok(())
    }
}

impl<P: Preset> Aggregate for Attestation<P> {
    fn committee_vote(&self) -> CommitteeVote {
        Self::committee_vote(self)
    }

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

impl SlashingEvidence for AttesterSlashing {
    fn conflicting_votes(&self) -> ConflictingVotes {
        Self::conflicting_votes(self)
    }

    fn votes(&self) -> [IndexedVote<'_>; 2] {
        [&self.attestation_1, &self.attestation_2].map(|attestation| IndexedVote {
            indices: &attestation.attesting_indices,
            data: &attestation.data,
            signature: &attestation.signature,
        })
    }
}

/// The payload timeliness committee of a slot, as the window of a state with builders holds it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ptc;

impl Ptc {
    /// The members for a slot of the previous, current, or next epoch, or nobody outside them.
    ///
    /// See `get_ptc` in the Gloas beacon chain spec.
    pub(crate) fn of<S: BuilderState + ?Sized>(state: &S, slot: Slot) -> Vec<ValidatorIndex> {
        let epoch = slot.epoch::<S::Preset>().0;
        let state_epoch = state.current_epoch().0;
        // The window holds the previous, current, and lookahead epochs, oldest first.
        let first = state_epoch.saturating_sub(1);
        let last = state_epoch + S::Preset::MIN_SEED_LOOKAHEAD;
        if epoch < first || epoch > last {
            return Vec::new();
        }
        let offset = if epoch < state_epoch {
            0
        } else {
            (epoch - state_epoch + 1) * S::Preset::SLOTS_PER_EPOCH
        };
        let position = (offset + slot.0 % S::Preset::SLOTS_PER_EPOCH) as usize;
        state
            .ptc_window()
            .get(position)
            .map(|committee| committee.to_vec())
            .unwrap_or_default()
    }
}

/// A builder's balance, net of what it already owes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BuilderFunds {
    /// The builder's balance.
    balance: Gwei,
    /// Withdrawals and payments the builder still owes.
    pending: Gwei,
}

impl BuilderFunds {
    /// The funds of a builder in a state, nothing for an unknown builder.
    ///
    /// See `get_pending_balance_to_withdraw_for_builder` in the Gloas beacon chain spec.
    pub(crate) fn of<S: BuilderState + ?Sized>(state: &S, index: BuilderIndex) -> Self {
        let balance = state
            .builders()
            .get(index.as_usize())
            .map_or(Gwei(0), |builder| builder.balance);
        let withdrawals = state
            .builder_pending_withdrawals()
            .iter()
            .filter(|withdrawal| withdrawal.builder_index == index)
            .map(|withdrawal| withdrawal.amount);
        let payments = state
            .builder_pending_payments()
            .iter()
            .filter(|payment| payment.withdrawal.builder_index == index)
            .map(|payment| payment.withdrawal.amount);
        let pending = withdrawals.chain(payments).fold(Gwei(0), |total, amount| {
            Gwei(total.0.saturating_add(amount.0))
        });
        Self { balance, pending }
    }

    /// Whether the builder keeps the minimum deposit after paying a bid and its debts.
    ///
    /// See `can_builder_cover_bid` in the Gloas beacon chain spec.
    pub(crate) const fn cover<P: Preset>(self, bid: Gwei) -> bool {
        let floor = P::MIN_DEPOSIT_AMOUNT.0.saturating_add(self.pending.0);
        self.balance.0 >= floor && self.balance.0 - floor >= bid.0
    }
}

/// A proposer's target gas limit, reached from the parent's limit in steps.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GasTarget {
    /// The parent payload's gas limit.
    parent: u64,
    /// The limit the proposer asks for.
    target: u64,
}

impl GasTarget {
    /// A target from a parent limit.
    pub(crate) const fn new(parent: u64, target: u64) -> Self {
        Self { parent, target }
    }

    /// Whether a gas limit is the step from the parent toward the target.
    ///
    /// EIP-1559 lets a block move the limit by just under 1/1024 of the parent's.
    /// See `is_gas_limit_target_compatible` in the Gloas p2p spec.
    pub(crate) const fn allows(self, gas_limit: u64) -> bool {
        let step = (self.parent / 1024).saturating_sub(1);
        let low = self.parent - step;
        let high = self.parent + step;
        if self.target < low {
            gas_limit == low
        } else if self.target > high {
            gas_limit == high
        } else {
            gas_limit == self.target
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        Minimal,
        gloas::{Builder, BuilderPendingPayment, BuilderPendingWithdrawal},
    };

    use super::*;

    #[test]
    fn the_gas_limit_moves_one_step_toward_the_target() {
        // A parent limit of 30_720_000 allows a step of 30_720_000 / 1024 - 1 = 29_999.
        let step = 29_999;
        let parent = 30_720_000;

        // A target within reach must be hit exactly.
        let near = GasTarget::new(parent, parent + 100);
        assert!(near.allows(parent + 100));
        assert!(!near.allows(parent + 99));

        // A target far above stops at one full step up, not one gas further.
        let high = GasTarget::new(parent, 60_000_000);
        assert!(high.allows(parent + step));
        assert!(!high.allows(parent + step + 1));

        // A target far below stops at one full step down.
        let low = GasTarget::new(parent, 1_000_000);
        assert!(low.allows(parent - step));
        assert!(!low.allows(parent - step - 1));
    }

    #[test]
    fn a_builder_keeps_its_minimum_deposit_and_its_debts() {
        // Fixture state: builder 0 holds 10 ETH, owes a 2 ETH withdrawal and a 3 ETH payment.
        let mut state = BeaconState::<Minimal>::default();
        state.builders.push(Builder {
            balance: Gwei(10_000_000_000),
            ..Builder::default()
        });
        state
            .builder_pending_withdrawals
            .push(BuilderPendingWithdrawal {
                amount: Gwei(2_000_000_000),
                ..BuilderPendingWithdrawal::default()
            });
        state.builder_pending_payments[0] = BuilderPendingPayment {
            withdrawal: BuilderPendingWithdrawal {
                amount: Gwei(3_000_000_000),
                ..BuilderPendingWithdrawal::default()
            },
            ..BuilderPendingPayment::default()
        };
        let funds = BuilderFunds::of(&state, BuilderIndex(0));

        // 10 - 1 (minimum deposit) - 2 - 3 leaves exactly 4 ETH to bid.
        assert!(funds.cover::<Minimal>(Gwei(4_000_000_000)));
        assert!(!funds.cover::<Minimal>(Gwei(4_000_000_001)));

        // An unknown builder has nothing, so it covers no bid at all.
        assert!(!BuilderFunds::of(&state, BuilderIndex(7)).cover::<Minimal>(Gwei(0)));
    }

    #[test]
    fn a_count_over_its_limit_is_rejected_with_both_sides() {
        assert_eq!(Bounded::new(3, 3, "too many").check(), Ok(()));
        assert_eq!(
            Bounded::new(4, 3, "too many").check(),
            Err(GossipError::Reject {
                reason: "too many",
                detail: Detail::Bound { value: 4, bound: 3 },
            })
        );
    }

    #[test]
    fn the_committee_window_covers_the_previous_through_the_lookahead_epoch() {
        // Fixture state: minimal epochs of 8 slots, the state in epoch 2 at slot 16.
        let mut state = BeaconState::<Minimal> {
            slot: Slot(16),
            ..BeaconState::default()
        };
        // Window rows: 0..8 epoch 1, 8..16 epoch 2, 16..24 epoch 3; row r names validator r.
        for (row, committee) in state.ptc_window.iter_mut().enumerate() {
            committee[0] = ValidatorIndex(row as u64);
        }

        // Slot 9 of epoch 1 reads row 1, slot 17 of epoch 2 row 9, slot 25 of epoch 3 row 17.
        assert_eq!(Ptc::of(&state, Slot(9))[0], ValidatorIndex(1));
        assert_eq!(Ptc::of(&state, Slot(17))[0], ValidatorIndex(9));
        assert_eq!(Ptc::of(&state, Slot(25))[0], ValidatorIndex(17));

        // Epochs 0 and 4 are outside the window, so nobody sits on their committees.
        assert_eq!(Ptc::of(&state, Slot(7)), Vec::new());
        assert_eq!(Ptc::of(&state, Slot(32)), Vec::new());
    }
}
