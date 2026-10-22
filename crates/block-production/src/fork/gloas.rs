//! Gloas blocks: a bid for the payload in place of the payload, which follows in an envelope.

use axiom_ssz::{ProgressiveList, Ssz};
use axiom_state_transition::{
    BlockProcessor, KnownVerdict, State, Verification,
    gloas::block::{ExpectedWithdrawals, ParentPayload as ParentPayloadRule},
};
use axiom_types::{
    Gwei, Preset, Root,
    accessors::{BuilderState, CoreState, ForkState},
    capella::Withdrawal,
    combined,
    constants::{BUILDER_INDEX_SELF_BUILD, G2_POINT_AT_INFINITY},
    gloas::{
        BeaconBlock, BeaconBlockBody, BeaconState, BlockContents, ExecutionPayloadBid,
        ExecutionPayloadEnvelope, ExecutionRequests, SignedExecutionPayloadBid,
        SignedExecutionPayloadEnvelope,
    },
};

use crate::{
    BlockFork, BodyParts, Built, ExecutionChoice, GloasBid, LocalPayload, ParentPayload,
    ProducedBlock, ProductionError, Trial,
};

impl<P: Preset> BlockFork for BeaconState<P> {
    /// Gloas takes no deposit from the contract, so the vote has nothing left to decide.
    fn bridge_closed(_state: &Self) -> bool {
        true
    }

    /// Withdrawals after the parent's payload, or those the parent left due when it is empty.
    ///
    /// See `prepare_execution_payload` in the Gloas validator spec.
    fn withdrawals_due(
        trial: &Trial<'_, P>,
        parent: &ParentPayload,
    ) -> Result<Vec<Withdrawal>, ProductionError> {
        match parent {
            ParentPayload::Empty => {
                let state = Self::from_any(trial.state().beacon())
                    .ok_or(ProductionError::WrongState(Self::FORK))?;
                Ok(state.payload_expected_withdrawals().to_vec())
            }
            ParentPayload::Full(_) => {
                let settled = ParentSettlement::apply(trial, parent)?;
                let gloas = Self::from_any(settled.beacon())
                    .ok_or(ProductionError::WrongState(Self::FORK))?;
                let expected =
                    ExpectedWithdrawals::compute(gloas).map_err(ProductionError::Withdrawals)?;
                Ok(expected.withdrawals)
            }
        }
    }

    /// The block settles its parent's payload before its operations.
    ///
    /// A request in that payload can change whether an exit or a vote is valid.
    fn packing_state(
        trial: &Trial<'_, P>,
        execution: &ExecutionChoice<P>,
    ) -> Result<Option<State<P>>, ProductionError> {
        let ExecutionChoice::Gloas { parent, .. } = execution else {
            return Err(execution.mismatch(Self::FORK));
        };
        ParentSettlement::apply(trial, parent).map(Some)
    }

    fn build(
        trial: &Trial<'_, P>,
        parts: &BodyParts<Self>,
        execution: ExecutionChoice<P>,
    ) -> Result<Built<P>, ProductionError> {
        let ExecutionChoice::Gloas { parent, bid } = execution else {
            return Err(execution.mismatch(Self::FORK));
        };
        let state = Self::from_any(trial.state().beacon())
            .ok_or(ProductionError::WrongState(Self::FORK))?;
        let latest = state.latest_execution_payload_bid();
        let (parent_block_hash, parent_execution_requests) = match parent {
            ParentPayload::Full(requests) => (latest.block_hash, requests),
            ParentPayload::Empty => (latest.parent_block_hash, ExecutionRequests::default()),
        };
        let (signed_bid, revealed) = match bid {
            GloasBid::Builder(signed) => (*signed, None),
            GloasBid::SelfBuild(build) => {
                let build = *build;
                let LocalPayload::Gloas {
                    payload,
                    blobs,
                    requests,
                } = build.payload
                else {
                    return Err(ExecutionChoice::Local(build).mismatch(Self::FORK));
                };
                // A self-built bid pays nothing and carries the point at infinity as signature.
                // See the Gloas validator spec, section on the signed execution payload bid.
                let bid = ExecutionPayloadBid {
                    parent_block_hash,
                    parent_block_root: parts.parent_root,
                    block_hash: payload.block_hash,
                    prev_randao: payload.prev_randao,
                    fee_recipient: payload.fee_recipient,
                    gas_limit: payload.gas_limit,
                    builder_index: BUILDER_INDEX_SELF_BUILD,
                    slot: parts.slot,
                    value: Gwei::ZERO,
                    execution_payment: Gwei::ZERO,
                    blob_kzg_commitments: ProgressiveList::from(blobs.commitments.to_vec()),
                    execution_requests_root: requests.hash_tree_root(),
                };
                let signed = SignedExecutionPayloadBid {
                    message: bid,
                    signature: G2_POINT_AT_INFINITY,
                };
                (signed, Some((payload, blobs, requests)))
            }
        };
        let assembly = Assembly {
            parts,
            bid: &signed_bid,
            parent_execution_requests: &parent_execution_requests,
        };
        let (block, post) = trial.settle(
            |state_root| Ok(assembly.block(state_root)),
            |block| combined::BeaconBlock::Gloas(block.clone()),
        )?;
        let Some((payload, blobs, requests)) = revealed else {
            return Ok(Built {
                block: ProducedBlock::Gloas(block),
                post,
            });
        };

        // The envelope reveals the payload the self-built bid committed to.
        // Checking it against the post-state catches withdrawals other than those due.
        let envelope = ExecutionPayloadEnvelope {
            payload,
            execution_requests: requests,
            builder_index: BUILDER_INDEX_SELF_BUILD,
            beacon_block_root: block.hash_tree_root(),
            parent_beacon_block_root: block.parent_root,
        };
        let unsigned = SignedExecutionPayloadEnvelope {
            message: envelope,
            signature: G2_POINT_AT_INFINITY,
        };
        post.clone()
            .verify_execution_payload_envelope(
                trial.config(),
                &unsigned,
                Verification::Skip,
                &KnownVerdict(true),
            )
            .map_err(|source| ProductionError::Envelope {
                slot: parts.slot,
                source,
            })?;
        let contents = BlockContents {
            block,
            execution_payload_envelope: unsigned.message,
            kzg_proofs: blobs.proofs,
            blobs: blobs.blobs,
        };
        Ok(Built {
            block: ProducedBlock::GloasContents(contents),
            post,
        })
    }
}

/// The state at the block's slot after its parent's payload is settled.
///
/// Settling applies the parent's execution requests, as the block's processing does first.
/// See `process_parent_execution_payload` in the Gloas beacon chain spec.
#[derive(Clone, Copy, Debug)]
struct ParentSettlement;

impl ParentSettlement {
    /// A copy of the state with the parent's payload settled, or untouched for an empty parent.
    fn apply<P: Preset>(
        trial: &Trial<'_, P>,
        parent: &ParentPayload,
    ) -> Result<State<P>, ProductionError> {
        let mut settled = trial.state().clone();
        let ParentPayload::Full(requests) = parent else {
            return Ok(settled);
        };
        let fork = settled.fork_name();
        let slot = settled.beacon().slot();
        let latest_block_hash = BeaconState::<P>::from_any(settled.beacon())
            .ok_or(ProductionError::WrongState(fork))?
            .latest_execution_payload_bid()
            .block_hash;
        // Only the bid's parent hash and the requests matter to the rule.
        let mut body = BeaconBlockBody::<P>::default();
        body.signed_execution_payload_bid.message.parent_block_hash = latest_block_hash;
        body.parent_execution_requests = requests.clone();
        let cached = settled
            .of_fork::<BeaconState<P>>()
            .ok_or(ProductionError::WrongState(fork))?;
        let mut processor = BlockProcessor::new(cached, trial.config(), Verification::Skip);
        processor
            .apply(&ParentPayloadRule::of(&body))
            .map_err(|source| ProductionError::ParentPayload { slot, source })?;
        Ok(settled)
    }
}

/// The parts of a Gloas block, put in Gloas's containers.
#[derive(Clone, Copy, Debug)]
struct Assembly<'a, P: Preset> {
    /// The parts every fork shares.
    parts: &'a BodyParts<BeaconState<P>>,
    /// The bid the block commits to.
    bid: &'a SignedExecutionPayloadBid,
    /// The requests of the parent's payload, empty when the parent is empty.
    parent_execution_requests: &'a ExecutionRequests,
}

impl<P: Preset> Assembly<'_, P> {
    /// The block, claiming a state root.
    ///
    /// Gloas lists are progressive, so they have no bound to overflow.
    /// Block processing checks the operation limits instead.
    fn block(self, state_root: Root) -> BeaconBlock<P> {
        let parts = self.parts;
        let operations = &parts.operations;
        BeaconBlock {
            slot: parts.slot,
            proposer_index: parts.proposer_index,
            parent_root: parts.parent_root,
            state_root,
            body: BeaconBlockBody {
                randao_reveal: parts.randao_reveal,
                eth1_data: parts.eth1_data.clone(),
                graffiti: parts.graffiti,
                proposer_slashings: operations.proposer_slashings.clone().into(),
                attester_slashings: operations.attester_slashings.clone().into(),
                attestations: operations.attestations.clone().into(),
                deposits: parts.deposits.clone().into(),
                voluntary_exits: operations.voluntary_exits.clone().into(),
                sync_aggregate: parts.sync_aggregate.clone(),
                bls_to_execution_changes: operations.bls_to_execution_changes.clone().into(),
                signed_execution_payload_bid: self.bid.clone(),
                payload_attestations: parts.payload_attestations.clone().into(),
                parent_execution_requests: self.parent_execution_requests.clone(),
            },
        }
    }
}
