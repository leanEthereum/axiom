//! Altair: sync committees and participation flags.
//!
//! The steps here are the ones Altair introduced or rewrote and no later fork rewrote again.

pub mod block;
pub mod epoch;
pub mod flags;
mod upgrade;

use axiom_types::{
    Preset, ValidatorIndex,
    accessors::{ForkState, ParticipationState, SyncCommitteeState},
    altair::{BeaconBlock, BeaconState},
    phase0::BeaconBlockHeader,
};

use crate::{
    BlockError, BlockProcessor, EpochProcessor, EpochStep, Fork, PayloadEngine, Registry,
    StateError,
    altair::epoch::{
        FlagRotation, InactivityUpdates, Participation, RewardsAndPenalties, SyncCommitteeRotation,
    },
    phase0::{ExitQueue, Slashing, SlotRoots, epoch::Rollover},
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

/// The epoch steps Altair defined, shared by every fork that keeps participation flags.
///
/// A fork's epoch processing hands the steps it inherits from Altair to this type.
#[derive(Clone, Copy, Debug)]
pub struct AltairEpoch;

impl AltairEpoch {
    /// Runs a step Altair or phase0 defined, or reports the step as one the fork must write.
    ///
    /// # Errors
    ///
    /// Fails when the state breaks an invariant, or the fork has no rule for the step here.
    pub fn run<S>(processor: &mut EpochProcessor<'_, S>, step: EpochStep) -> Result<(), StateError>
    where
        S: Fork + ParticipationState + SyncCommitteeState,
    {
        let current = processor.current_epoch;
        let total = processor.total_active_balance;
        match step {
            EpochStep::JustificationAndFinalization => {
                let justification =
                    Participation::new(&*processor.state.beacon, total).justification();
                justification.weigh(&mut *processor.state.beacon)
            }
            EpochStep::InactivityUpdates => {
                InactivityUpdates::new(
                    &Participation::new(&*processor.state.beacon, total),
                    processor.config,
                )
                .apply(&mut *processor.state.beacon);
                Ok(())
            }
            EpochStep::RewardsAndPenalties => RewardsAndPenalties::new(
                &Participation::new(&*processor.state.beacon, total),
                processor.config,
            )
            .apply(&mut processor.state),
            EpochStep::Eth1DataReset => {
                Rollover::new(current).reset_eth1_data(&mut *processor.state.beacon);
                Ok(())
            }
            EpochStep::SlashingsReset => {
                Rollover::new(current).reset_slashings(&mut *processor.state.beacon);
                Ok(())
            }
            EpochStep::RandaoMixesReset => {
                Rollover::new(current).reset_randao_mix(&mut *processor.state.beacon);
                Ok(())
            }
            EpochStep::ParticipationFlagUpdates => {
                FlagRotation.apply(&mut *processor.state.beacon);
                Ok(())
            }
            EpochStep::SyncCommitteeUpdates => {
                SyncCommitteeRotation::new(current).apply(&mut processor.state)
            }
            _ => Err(EpochProcessor::<S>::unsupported(step)),
        }
    }
}
