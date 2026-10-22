//! Altair: sync committees and participation flags.
//!
//! The steps here are the ones Altair introduced or rewrote and no later fork rewrote again.

pub mod block;
pub mod epoch;
pub mod flags;
mod upgrade;

use axiom_types::{
    ChainConfig, Preset, ValidatorIndex,
    accessors::{ForkState, ParticipationState, SyncCommitteeState},
    altair::{BeaconBlock, BeaconState},
    phase0::BeaconBlockHeader,
};

use crate::{
    ActiveBalance, BlockError, BlockProcessor, CachedState, EpochProcessor, EpochStep, EpochVotes,
    Fork, PayloadEngine, Registry, StateError,
    altair::{
        block::{FlaggedAttestation, ParticipantDeposit},
        epoch::{
            FlagRotation, InactivityUpdates, Participation, RewardsAndPenalties,
            SyncCommitteeRotation,
        },
    },
    phase0::{
        ExitQueue, Phase0Epoch, Slashing, SlotRoots,
        block::{DepositQuota, RandaoReveal},
    },
    rewards::AttesterRewards,
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

    fn attester_rewards(
        state: CachedState<'_, Self>,
        config: &ChainConfig,
    ) -> Result<AttesterRewards, StateError> {
        Ok(AltairEpoch::attester_rewards(state.beacon(), config))
    }

    fn previous_epoch_votes(state: CachedState<'_, Self>) -> Result<EpochVotes, StateError> {
        Ok(EpochVotes::of_participation(state.beacon()))
    }

    /// Runs Altair's block processing.
    ///
    /// 1. The header, the RANDAO reveal, and the eth1 vote, by phase0's rules.
    /// 2. The slashings, by phase0's rules under Altair's penalty constants.
    /// 3. The attestations, credited in participation flags.
    /// 4. The deposits, registering validators with participation flags.
    /// 5. The voluntary exits, by phase0's rule.
    /// 6. The sync aggregate.
    ///
    /// See `process_block` and `process_operations` in the Altair beacon chain spec.
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
            processor.apply(&FlaggedAttestation(attestation))?;
        }
        for deposit in &body.deposits {
            processor.apply(&ParticipantDeposit(deposit))?;
        }
        processor.apply_all(&body.voluntary_exits)?;

        processor.apply(&body.sync_aggregate)
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
            EpochStep::ParticipationFlagUpdates => {
                FlagRotation.apply(&mut *processor.state.beacon);
                Ok(())
            }
            EpochStep::SyncCommitteeUpdates => {
                SyncCommitteeRotation::new(current).apply(&mut processor.state)
            }
            _ => Phase0Epoch::run(processor, step),
        }
    }

    /// The attestation rewards of a state's previous epoch, scored by participation flags.
    #[must_use]
    pub fn attester_rewards<S>(state: &S, config: &ChainConfig) -> AttesterRewards
    where
        S: ParticipationState + ForkState,
    {
        let participation = Participation::new(state, ActiveBalance::of(state));
        AttesterRewards::of_participation(&participation, config)
    }
}
