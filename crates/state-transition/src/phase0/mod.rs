//! Phase0: the launch of the beacon chain, and the rules every later fork starts from.
//!
//! The steps here are the ones no later fork rewrote.
//! Later forks call them directly, generic over the field groups they read.

pub mod block;
pub mod epoch;
mod exits;
mod genesis;
mod slashing;
mod slot;

use axiom_types::{
    ChainConfig, Preset, ValidatorIndex,
    phase0::{BeaconBlock, BeaconBlockHeader, BeaconState},
};
pub use exits::ExitQueue;
pub use genesis::Genesis;
pub use slashing::Slashing;
pub use slot::SlotRoots;

use crate::{
    ActiveBalance, BlockError, BlockProcessor, CachedState, EpochProcessor, EpochStep, Fork,
    PayloadEngine, Registry, StateError,
    phase0::{
        block::{AttestationRecord, DepositQuota, RandaoReveal},
        epoch::{
            AttestationRewards, CorrelationPenalty, HistoricalRootsUpdate, Hysteresis,
            Justification, PendingParticipation, RegistryUpdates, RewardsAndPenalties, Rollover,
        },
    },
    rewards::AttesterRewards,
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
        let total = processor.total_active_balance;
        match step {
            EpochStep::JustificationAndFinalization => {
                if !Justification::applies_at(processor.current_epoch) {
                    return Ok(());
                }
                let participation = PendingParticipation::new(&mut processor.state, total)?;
                participation
                    .justification()
                    .weigh(&mut *processor.state.beacon)
            }
            EpochStep::RewardsAndPenalties => {
                RewardsAndPenalties::new(processor.current_epoch, total).apply(&mut processor.state)
            }
            EpochStep::ParticipationRecordUpdates => {
                Rollover::new(processor.current_epoch)
                    .rotate_pending_attestations(&mut *processor.state.beacon);
                Ok(())
            }
            _ => Phase0Epoch::run(processor, step),
        }
    }

    fn attester_rewards(
        mut state: CachedState<'_, Self>,
        _config: &ChainConfig,
    ) -> Result<AttesterRewards, StateError> {
        let total = ActiveBalance::of(state.beacon());
        let participation = PendingParticipation::new(&mut state, total)?;
        let rewards = AttestationRewards::new(state.beacon(), &participation);
        AttesterRewards::of_pending(&rewards, state.beacon())
    }

    /// Runs phase0's block processing.
    ///
    /// 1. The header, the RANDAO reveal, and the eth1 vote.
    /// 2. Every outstanding deposit must be included, up to the block's limit.
    /// 3. The operations, in the order the spec lists them.
    ///
    /// See `process_block` and `process_operations` in the phase0 beacon chain spec.
    fn process_block<E: PayloadEngine<P>>(
        processor: &mut BlockProcessor<'_, Self>,
        block: &BeaconBlock<P>,
        header: &BeaconBlockHeader,
        _engine: &E,
    ) -> Result<(), BlockError> {
        let body = &block.body;
        processor.apply(header)?;
        processor.apply(&RandaoReveal(body.randao_reveal))?;
        processor.apply(&body.eth1_data)?;

        DepositQuota::of(processor.state.beacon()).check(body.deposits.len())?;
        processor.apply_all(&body.proposer_slashings)?;
        processor.apply_all(&body.attester_slashings)?;
        for attestation in &body.attestations {
            processor.apply(&AttestationRecord(attestation))?;
        }
        processor.apply_all(&body.deposits)?;
        processor.apply_all(&body.voluntary_exits)
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
