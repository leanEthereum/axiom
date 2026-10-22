//! Bellatrix blocks: Altair's, with an execution payload, local or from a builder.

use axiom_ssz::List;
use axiom_types::{
    Preset, Root,
    accessors::ForkState,
    bellatrix::{
        BeaconBlock, BeaconBlockBody, BeaconState, BlindedBeaconBlock, ExecutionPayload,
        ExecutionPayloadHeader,
    },
    combined,
};

use crate::{
    BlockFork, BodyParts, Bounded, Built, ExecutionChoice, LocalPayload, ProducedBlock,
    ProductionError, Trial, fork::BuilderHeader,
};

impl<P: Preset> BlockFork for BeaconState<P> {
    fn build(
        trial: &Trial<'_, P>,
        parts: &BodyParts<Self>,
        execution: ExecutionChoice<P>,
    ) -> Result<Built<P>, ProductionError> {
        let assembly = Assembly(parts);
        let combine = |block: &BeaconBlock<P>| combined::BeaconBlock::Bellatrix(block.clone());
        let payload = match execution {
            // Before the merge a block carries the empty payload.
            // See `is_merge_transition_complete` in the Bellatrix beacon chain spec.
            ExecutionChoice::PreMerge if !trial.state().beacon().is_merge_transition_complete() => {
                ExecutionPayload::default()
            }
            ExecutionChoice::Local(build) => match build.payload {
                LocalPayload::Bellatrix(payload) => payload,
                _ => return Err(ExecutionChoice::Local(build).mismatch(Self::FORK)),
            },
            ExecutionChoice::Builder(combined::SignedBuilderBid::Bellatrix(bid)) => {
                let header = bid.message.header;
                let stand_in = Assembly::<P>::stand_in(&header);
                let (_, mut post) =
                    trial.apply(&combine(&assembly.block(Root::ZERO, &stand_in)?))?;
                let state_root = BuilderHeader::<Self>(header.clone()).commit(&mut post);
                let mut blinded = BlindedBeaconBlock::from(assembly.block(state_root, &stand_in)?);
                blinded.body.execution_payload_header = header;
                let blinded = combined::BlindedBeaconBlock::Bellatrix(blinded);
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
            block: ProducedBlock::Bellatrix(block),
            post,
        })
    }
}

/// The parts of a Bellatrix block, put in Bellatrix's containers.
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
            },
        })
    }

    /// A payload with a header's fields and no transactions, for the trial of a blinded block.
    fn stand_in(header: &ExecutionPayloadHeader<P>) -> ExecutionPayload<P> {
        ExecutionPayload {
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
        }
    }
}
