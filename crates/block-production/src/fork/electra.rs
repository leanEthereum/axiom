//! Electra blocks: Deneb's, with multi-committee attestations and execution requests.

use axiom_ssz::{List, Ssz};
use axiom_state_transition::electra::block::ExpectedWithdrawals;
use axiom_types::{
    KzgCommitment, Preset, Root,
    accessors::{ForkState, PendingQueueState},
    capella::{Withdrawal, Withdrawals},
    combined,
    electra::{
        BeaconBlock, BeaconBlockBody, BeaconState, BlindedBeaconBlock, BlockContents,
        ExecutionPayload, ExecutionPayloadHeader, ExecutionRequests,
    },
};

use crate::{
    BlockFork, BodyParts, Bounded, Built, ExecutionChoice, LocalPayload, ParentPayload,
    ProducedBlock, ProductionError, Trial, fork::BuilderHeader,
};

impl<P: Preset> BlockFork for BeaconState<P> {
    const CARRIES_WITHDRAWALS: bool = true;

    /// The vote stops once every contract deposit is bridged, see EIP-6110.
    fn bridge_closed(state: &Self) -> bool {
        state.eth1_deposit_index == state.deposit_requests_start_index()
    }

    /// Electra's withdrawals: pending partial withdrawals first, then the sweep.
    fn withdrawals_due(
        trial: &Trial<'_, P>,
        _parent: &ParentPayload,
    ) -> Result<Vec<Withdrawal>, ProductionError> {
        let state = Self::from_any(trial.state().beacon())
            .ok_or(ProductionError::WrongState(Self::FORK))?;
        let expected = ExpectedWithdrawals::compute(state).map_err(ProductionError::Withdrawals)?;
        Ok(expected.withdrawals)
    }

    fn build(
        trial: &Trial<'_, P>,
        parts: &BodyParts<Self>,
        execution: ExecutionChoice<P>,
    ) -> Result<Built<P>, ProductionError> {
        let assembly = Assembly(parts);
        let combine = |block: &BeaconBlock<P>| combined::BeaconBlock::Electra(block.clone());
        let (payload, blobs, requests) = match execution {
            ExecutionChoice::Local(build) => match build.payload {
                LocalPayload::Electra {
                    payload,
                    blobs,
                    requests,
                } => (payload, blobs, requests),
                _ => return Err(ExecutionChoice::Local(build).mismatch(Self::FORK)),
            },
            ExecutionChoice::Builder(combined::SignedBuilderBid::Electra(bid)) => {
                let bid = bid.message;
                let header = bid.header;
                let payload = Payload {
                    execution: &Assembly::<P>::stand_in(trial, &header)?,
                    commitments: bid.blob_kzg_commitments.as_slice(),
                    requests: &bid.execution_requests,
                };
                let draft = assembly.block(Root::ZERO, payload)?;
                let (_, mut post) = trial.apply(&combine(&draft))?;
                let mut blinded = BlindedBeaconBlock::from(draft);
                blinded.body.execution_payload_header = header.clone();
                let body_root = blinded.body.hash_tree_root();
                blinded.state_root = BuilderHeader::<Self>(header).commit(&mut post, body_root);
                let blinded = combined::BlindedBeaconBlock::Electra(blinded);
                return Ok(Built {
                    block: ProducedBlock::Blinded(blinded),
                    post,
                });
            }
            other => return Err(other.mismatch(Self::FORK)),
        };
        let payload = Payload {
            execution: &payload,
            commitments: blobs.commitments.as_slice(),
            requests: &requests,
        };
        let (block, post) =
            trial.settle(|state_root| assembly.block(state_root, payload), combine)?;
        let contents = BlockContents {
            block,
            kzg_proofs: blobs.proofs.clone(),
            blobs: blobs.blobs.clone(),
        };
        Ok(Built {
            block: ProducedBlock::Electra(contents),
            post,
        })
    }
}

/// The execution side of an Electra block.
#[derive(Clone, Copy, Debug)]
struct Payload<'a, P: Preset> {
    /// The payload.
    execution: &'a ExecutionPayload<P>,
    /// Commitments to its blobs.
    commitments: &'a [KzgCommitment],
    /// Its requests.
    requests: &'a ExecutionRequests<P>,
}

/// The parts of an Electra block, put in Electra's containers.
#[derive(Clone, Copy, Debug)]
struct Assembly<'a, P: Preset>(&'a BodyParts<BeaconState<P>>);

impl<P: Preset> Assembly<'_, P> {
    /// The block with its execution side, claiming a state root.
    fn block(
        self,
        state_root: Root,
        payload: Payload<'_, P>,
    ) -> Result<BeaconBlock<P>, ProductionError> {
        let parts = self.0;
        let operations = &parts.operations;
        Ok(BeaconBlock {
            slot: parts.slot,
            proposer_index: parts.proposer_index,
            parent_root: parts.parent_root,
            state_root,
            body: BeaconBlockBody {
                randao_reveal: parts.randao_reveal,
                eth1_data: parts.eth1_data.clone(),
                graffiti: parts.graffiti,
                proposer_slashings: Bounded::list(
                    "proposer slashings",
                    &operations.proposer_slashings,
                )?,
                attester_slashings: Bounded::list(
                    "attester slashings",
                    &operations.attester_slashings,
                )?,
                attestations: Bounded::list("attestations", &operations.attestations)?,
                deposits: Bounded::list("deposits", &parts.deposits)?,
                voluntary_exits: Bounded::list("voluntary exits", &operations.voluntary_exits)?,
                sync_aggregate: parts.sync_aggregate.clone(),
                execution_payload: payload.execution.clone(),
                bls_to_execution_changes: Bounded::list(
                    "credential changes",
                    &operations.bls_to_execution_changes,
                )?,
                blob_kzg_commitments: Bounded::list("blob commitments", payload.commitments)?,
                execution_requests: payload.requests.clone(),
            },
        })
    }

    /// A payload with a header's fields, the withdrawals due, and no transactions.
    ///
    /// # Errors
    ///
    /// Fails when the header commits to other withdrawals than those due.
    fn stand_in(
        trial: &Trial<'_, P>,
        header: &ExecutionPayloadHeader<P>,
    ) -> Result<ExecutionPayload<P>, ProductionError> {
        let due = BeaconState::<P>::withdrawals_due(trial, &ParentPayload::Empty)?;
        let withdrawals: Withdrawals<P> = Bounded::list("withdrawals", &due)?;
        let expected = withdrawals.hash_tree_root();
        if header.withdrawals_root != expected {
            return Err(ProductionError::WithdrawalsMismatch {
                committed: header.withdrawals_root,
                expected,
            });
        }
        Ok(ExecutionPayload {
            parent_hash: header.parent_hash,
            fee_recipient: header.fee_recipient,
            state_root: header.state_root,
            receipts_root: header.receipts_root,
            logs_bloom: header.logs_bloom.clone(),
            prev_randao: header.prev_randao,
            block_number: header.block_number,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            timestamp: header.timestamp,
            extra_data: header.extra_data.clone(),
            base_fee_per_gas: header.base_fee_per_gas,
            block_hash: header.block_hash,
            transactions: List::default(),
            withdrawals,
            blob_gas_used: header.blob_gas_used,
            excess_blob_gas: header.excess_blob_gas,
        })
    }
}
