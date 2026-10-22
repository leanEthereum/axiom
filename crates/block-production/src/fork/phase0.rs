//! Phase0 blocks: votes and operations, no payload.

use axiom_types::{
    Preset, Root,
    accessors::ForkState,
    combined,
    phase0::{BeaconBlock, BeaconBlockBody, BeaconState},
};

use crate::{
    BlockFork, BodyParts, Bounded, Built, ExecutionChoice, ProducedBlock, ProductionError, Trial,
};

impl<P: Preset> BlockFork for BeaconState<P> {
    fn build(
        trial: &Trial<'_, P>,
        parts: &BodyParts<Self>,
        execution: ExecutionChoice<P>,
    ) -> Result<Built<P>, ProductionError> {
        if execution != ExecutionChoice::PreMerge {
            return Err(execution.mismatch(Self::FORK));
        }
        let assembly = Assembly(parts);
        let (block, post) = trial.settle(
            |state_root| assembly.block(state_root),
            |block| combined::BeaconBlock::Phase0(block.clone()),
        )?;
        Ok(Built {
            block: ProducedBlock::Phase0(block),
            post,
        })
    }
}

/// The parts of a phase0 block, put in phase0's containers.
#[derive(Clone, Copy, Debug)]
struct Assembly<'a, P: Preset>(&'a BodyParts<BeaconState<P>>);

impl<P: Preset> Assembly<'_, P> {
    /// The block, claiming a state root.
    fn block(self, state_root: Root) -> Result<BeaconBlock<P>, ProductionError> {
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
            },
        })
    }
}
