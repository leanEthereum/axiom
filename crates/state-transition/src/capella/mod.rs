//! Capella: withdrawals, credential changes, and historical summaries.

pub mod block;
pub mod epoch;
mod upgrade;

use axiom_types::{
    ChainConfig, Preset, ValidatorIndex,
    capella::{BeaconBlock, BeaconState, BlindedBeaconBlock},
    phase0::BeaconBlockHeader,
};

use crate::{
    BlindedFork, BlockError, BlockProcessor, CachedState, EpochProcessor, EpochStep, EpochVotes,
    Fork, PayloadEngine, Registry, StateError,
    altair::AltairEpoch,
    capella::{
        block::{BodyOperations, PayloadExecution, PayloadWithdrawals},
        epoch::HistoricalSummaryUpdate,
    },
    phase0::{ExitQueue, Slashing, SlotRoots},
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
        EpochStep::HistoricalSummariesUpdate,
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
        match step {
            EpochStep::HistoricalSummariesUpdate => {
                HistoricalSummaryUpdate::new(processor.current_epoch)
                    .apply(&mut *processor.state.beacon)
            }
            _ => AltairEpoch::run(processor, step),
        }
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

    /// Runs Capella's block processing.
    ///
    /// 1. The header.
    /// 2. The withdrawals and the execution payload, by Capella's rules.
    /// 3. The RANDAO reveal and the eth1 vote, by phase0's rules.
    /// 4. The operations, with attestations and deposits by Altair's rules.
    /// 5. The sync aggregate, by Altair's rule.
    ///
    /// Capella runs the payload steps unconditionally, since every chain had merged.
    /// See `process_block` and `process_operations` in the Capella beacon chain spec.
    fn process_block<E: PayloadEngine<P>>(
        processor: &mut BlockProcessor<'_, Self>,
        block: &BeaconBlock<P>,
        header: &BeaconBlockHeader,
        engine: &E,
    ) -> Result<(), BlockError> {
        let body = &block.body;
        let payload = &body.execution_payload;
        processor.apply(header)?;
        processor.apply(&PayloadWithdrawals::listed(&payload.withdrawals))?;
        processor.apply(&PayloadExecution::new(payload, engine))?;
        BodyOperations::from(body).apply(processor)
    }
}

impl<P: Preset> BlindedFork for BeaconState<P> {
    type BlindedBlock = BlindedBeaconBlock<P>;

    fn blinded_block_header(block: &BlindedBeaconBlock<P>) -> BeaconBlockHeader {
        block.header()
    }

    /// Runs Capella's block processing on a blinded block, its payload read from the header.
    fn process_blinded_block(
        processor: &mut BlockProcessor<'_, Self>,
        block: &BlindedBeaconBlock<P>,
        header: &BeaconBlockHeader,
    ) -> Result<(), BlockError> {
        let body = &block.body;
        let payload = &body.execution_payload_header;
        processor.apply(header)?;
        processor.apply(&PayloadWithdrawals::committed(payload.withdrawals_root))?;
        processor.apply(&PayloadExecution::blinded(payload))?;
        BodyOperations::from(body).apply(processor)
    }
}
