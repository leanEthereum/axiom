//! Bellatrix: the merge with the execution layer.
//!
//! Its penalty constants come from the fork's constant table; its other rules are Altair's.

mod upgrade;

use axiom_types::{
    Preset, ValidatorIndex,
    accessors::ForkState,
    bellatrix::{BeaconBlock, BeaconState},
    phase0::BeaconBlockHeader,
};

use crate::{
    BlockError, BlockProcessor, EpochProcessor, EpochStep, Fork, PayloadEngine, Registry,
    StateError,
    altair::AltairEpoch,
    phase0::{ExitQueue, Slashing, SlotRoots},
    sampling::WeightedSampler,
};

impl<P: Preset> Fork for BeaconState<P> {
    type Block = BeaconBlock<P>;

    const EPOCH_STEPS: &'static [EpochStep] = &[
        EpochStep::JustificationAndFinalization,
        EpochStep::InactivityUpdates,
        EpochStep::RewardsAndPenalties,
        EpochStep::RegistryUpdates,
        EpochStep::Slashings,
        EpochStep::Eth1DataReset,
        EpochStep::EffectiveBalanceUpdates,
        EpochStep::SlashingsReset,
        EpochStep::RandaoMixesReset,
        EpochStep::HistoricalRootsUpdate,
        EpochStep::ParticipationFlagUpdates,
        EpochStep::SyncCommitteeUpdates,
    ];

    fn block_header(block: &BeaconBlock<P>) -> BeaconBlockHeader {
        block.header()
    }

    fn beacon_proposer_index(state: &Self) -> Result<ValidatorIndex, StateError> {
        WeightedSampler::slot_proposer(state)
    }

    fn initiate_validator_exit(
        registry: &mut Registry<'_, Self>,
        index: ValidatorIndex,
    ) -> Result<(), StateError> {
        ExitQueue::initiate(registry, index)
    }

    fn slash_validator(
        registry: &mut Registry<'_, Self>,
        slashed: ValidatorIndex,
        whistleblower: Option<ValidatorIndex>,
    ) -> Result<(), StateError> {
        Slashing {
            slashed,
            whistleblower,
        }
        .apply(registry)
    }

    fn process_slot(state: &mut Self) {
        SlotRoots::of(state).record(state);
    }

    fn process_epoch_step(
        processor: &mut EpochProcessor<'_, Self>,
        step: EpochStep,
    ) -> Result<(), StateError> {
        AltairEpoch::run(processor, step)
    }

    fn process_block<E: PayloadEngine<P>>(
        _processor: &mut BlockProcessor<'_, Self>,
        _block: &BeaconBlock<P>,
        _header: &BeaconBlockHeader,
        _engine: &E,
    ) -> Result<(), BlockError> {
        Err(StateError::RulesMissing {
            fork: Self::FORK,
            rules: "block processing",
        }
        .into())
    }
}
