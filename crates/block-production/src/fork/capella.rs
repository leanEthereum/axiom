//! Capella blocks: Bellatrix's, with withdrawals in the payload and credential changes.

use axiom_ssz::{List, Ssz};
use axiom_state_transition::capella::block::ValidatorSweep;
use axiom_types::{
    Preset, Root,
    accessors::ForkState,
    capella::{
        BeaconBlock, BeaconBlockBody, BeaconState, BlindedBeaconBlock, ExecutionPayload,
        ExecutionPayloadHeader, Withdrawal, Withdrawals,
    },
    combined,
};

use crate::{
    BlockFork, BodyParts, Bounded, Built, ExecutionChoice, LocalPayload, ParentPayload,
    ProducedBlock, ProductionError, Trial, fork::BuilderHeader,
};

impl<P: Preset> BlockFork for BeaconState<P> {
    const CARRIES_WITHDRAWALS: bool = true;

    /// The validator sweep of Capella.
    fn withdrawals_due(
        trial: &Trial<'_, P>,
        _parent: &ParentPayload,
    ) -> Result<Vec<Withdrawal>, ProductionError> {
        let state = Self::from_any(trial.state().beacon())
            .ok_or(ProductionError::WrongState(Self::FORK))?;
        let sweep = ValidatorSweep::compute(state).map_err(ProductionError::Withdrawals)?;
        Ok(sweep.withdrawals)
    }

    fn build(
        trial: &Trial<'_, P>,
        parts: &BodyParts<Self>,
        execution: ExecutionChoice<P>,
    ) -> Result<Built<P>, ProductionError> {
        let assembly = Assembly(parts);
        let combine = |block: &BeaconBlock<P>| combined::BeaconBlock::Capella(block.clone());
        let payload = match execution {
            ExecutionChoice::Local(build) => match build.payload {
                LocalPayload::Capella(payload) => payload,
                _ => return Err(ExecutionChoice::Local(build).mismatch(Self::FORK)),
            },
            ExecutionChoice::Builder(combined::SignedBuilderBid::Capella(bid)) => {
                let header = bid.message.header;
                let stand_in = Assembly::<P>::stand_in(trial, &header)?;
                let draft = assembly.block(Root::ZERO, &stand_in)?;
                let (_, mut post) = trial.apply(&combine(&draft))?;
                let mut blinded = BlindedBeaconBlock::from(draft);
                blinded.body.execution_payload_header = header.clone();
                let body_root = blinded.body.hash_tree_root();
                blinded.state_root = BuilderHeader::<Self>(header).commit(&mut post, body_root);
                let blinded = combined::BlindedBeaconBlock::Capella(blinded);
                return Ok(Built {
                    block: ProducedBlock::Blinded(blinded),
                    post,
                });
            }
            other => return Err(other.mismatch(Self::FORK)),
        };
        let (block, post) =
            trial.settle(|state_root| assembly.block(state_root, &payload), combine)?;
        Ok(Built {
            block: ProducedBlock::Capella(block),
            post,
        })
    }
}

/// The parts of a Capella block, put in Capella's containers.
#[derive(Clone, Copy, Debug)]
struct Assembly<'a, P: Preset>(&'a BodyParts<BeaconState<P>>);

impl<P: Preset> Assembly<'_, P> {
    /// The block with a payload, claiming a state root.
    fn block(
        self,
        state_root: Root,
        payload: &ExecutionPayload<P>,
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
                execution_payload: payload.clone(),
                bls_to_execution_changes: Bounded::list(
                    "credential changes",
                    &operations.bls_to_execution_changes,
                )?,
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
        })
    }
}
