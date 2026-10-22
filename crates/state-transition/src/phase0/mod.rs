//! Phase0: the launch of the beacon chain, and the rules every later fork starts from.
//!
//! The steps here are the ones no later fork rewrote.
//! Later forks call them directly, generic over the field groups they read.

pub mod block;
pub mod epoch;
mod exits;
mod slashing;
mod slot;

use axiom_types::{
    Preset, ValidatorIndex,
    accessors::ForkState,
    phase0::{BeaconBlock, BeaconBlockHeader, BeaconState},
};
pub use exits::ExitQueue;
pub use slashing::Slashing;
pub use slot::SlotRoots;

use crate::{
    BlockError, BlockProcessor, EpochProcessor, EpochStep, Fork, PayloadEngine, Registry,
    StateError, phase0::epoch::Rollover, sampling::WeightedSampler,
};

impl<P: Preset> Fork for BeaconState<P> {
    type Block = BeaconBlock<P>;

    const EPOCH_STEPS: &'static [EpochStep] = &[
        EpochStep::JustificationAndFinalization,
        EpochStep::RewardsAndPenalties,
        EpochStep::RegistryUpdates,
        EpochStep::Slashings,
        EpochStep::Eth1DataReset,
        EpochStep::EffectiveBalanceUpdates,
        EpochStep::SlashingsReset,
        EpochStep::RandaoMixesReset,
        EpochStep::HistoricalRootsUpdate,
        EpochStep::ParticipationRecordUpdates,
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
        let rollover = Rollover::new(processor.current_epoch);
        let state = &mut *processor.state.beacon;
        match step {
            EpochStep::Eth1DataReset => rollover.reset_eth1_data(state),
            EpochStep::SlashingsReset => rollover.reset_slashings(state),
            EpochStep::RandaoMixesReset => rollover.reset_randao_mix(state),
            _ => return Err(EpochProcessor::<Self>::unsupported(step)),
        }
        Ok(())
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
