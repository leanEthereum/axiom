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
    StateError,
    phase0::epoch::{
        CorrelationPenalty, HistoricalRootsUpdate, Hysteresis, RegistryUpdates, Rollover,
    },
    sampling::WeightedSampler,
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
        Phase0Epoch::run(processor, step)
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

/// The epoch steps phase0 defined that read no participation records.
///
/// Later forks hand these steps to this type until they rewrite them.
/// The penalty constants come from the state's fork, through the fork's constant table.
#[derive(Clone, Copy, Debug)]
pub struct Phase0Epoch;

impl Phase0Epoch {
    /// Runs a step phase0 defined, or reports the step as one the fork must write.
    ///
    /// # Errors
    ///
    /// Fails when the state breaks an invariant, or the fork has no rule for the step here.
    pub fn run<S: Fork>(
        processor: &mut EpochProcessor<'_, S>,
        step: EpochStep,
    ) -> Result<(), StateError> {
        let current = processor.current_epoch;
        let rollover = Rollover::new(current);
        match step {
            EpochStep::RegistryUpdates => {
                RegistryUpdates::new(&*processor.state.beacon, processor.config)
                    .apply(&mut processor.registry())
            }
            EpochStep::Slashings => {
                CorrelationPenalty::new(&*processor.state.beacon, processor.total_active_balance)?
                    .apply(&mut processor.state)
            }
            EpochStep::Eth1DataReset => {
                rollover.reset_eth1_data(&mut *processor.state.beacon);
                Ok(())
            }
            EpochStep::EffectiveBalanceUpdates => {
                Hysteresis::new::<S::Preset>().apply(&mut *processor.state.beacon);
                Ok(())
            }
            EpochStep::SlashingsReset => {
                rollover.reset_slashings(&mut *processor.state.beacon);
                Ok(())
            }
            EpochStep::RandaoMixesReset => {
                rollover.reset_randao_mix(&mut *processor.state.beacon);
                Ok(())
            }
            EpochStep::HistoricalRootsUpdate => {
                HistoricalRootsUpdate::new(current).apply(&mut *processor.state.beacon)
            }
            _ => Err(EpochProcessor::<S>::unsupported(step)),
        }
    }
}
