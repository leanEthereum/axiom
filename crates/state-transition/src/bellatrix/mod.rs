//! Bellatrix: the merge with the execution layer.
//!
//! It adds the execution payload, and raises the penalties through the fork's constant table.
//! Its other rules are Altair's.

pub mod block;
mod upgrade;

use axiom_types::{
    ChainConfig, Preset, ValidatorIndex,
    accessors::ExecutionHeaderState,
    bellatrix::{BeaconBlock, BeaconState, BlindedBeaconBlock},
    phase0::BeaconBlockHeader,
};

use crate::{
    BlindedFork, BlockError, BlockProcessor, CachedState, EpochProcessor, EpochStep, EpochVotes,
    Fork, PayloadEngine, Registry, StateError,
    altair::AltairEpoch,
    bellatrix::block::{BodyOperations, PayloadExecution},
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

    /// Runs Bellatrix's block processing.
    ///
    /// 1. The header, by phase0's rule.
    /// 2. The execution payload, once the merge is done or in the block that makes it.
    /// 3. The RANDAO reveal and the eth1 vote, by phase0's rules.
    /// 4. The operations, by Altair's rules under Bellatrix's penalty constants.
    /// 5. The sync aggregate, by Altair's rule.
    ///
    /// The payload comes before the reveal, since it carries the mix the previous block left.
    /// See `process_block` in the Bellatrix beacon chain spec.
    fn process_block<E: PayloadEngine<P>>(
        processor: &mut BlockProcessor<'_, Self>,
        block: &BeaconBlock<P>,
        header: &BeaconBlockHeader,
        engine: &E,
    ) -> Result<(), BlockError> {
        let body = &block.body;
        processor.apply(header)?;
        let payload = PayloadExecution::new(body, engine);
        let latest = processor.state.beacon().latest_execution_payload_header();
        if payload.is_execution_enabled(latest) {
            processor.apply(&payload)?;
        }
        BodyOperations::from(body).apply(processor)
    }
}

impl<P: Preset> BlindedFork for BeaconState<P> {
    type BlindedBlock = BlindedBeaconBlock<P>;

    fn blinded_block_header(block: &BlindedBeaconBlock<P>) -> BeaconBlockHeader {
        block.header()
    }

    /// Runs Bellatrix's block processing on a blinded block, its payload read from the header.
    fn process_blinded_block(
        processor: &mut BlockProcessor<'_, Self>,
        block: &BlindedBeaconBlock<P>,
        header: &BeaconBlockHeader,
    ) -> Result<(), BlockError> {
        let body = &block.body;
        processor.apply(header)?;
        let payload = PayloadExecution::blinded(body);
        let latest = processor.state.beacon().latest_execution_payload_header();
        if payload.is_execution_enabled(latest) {
            processor.apply(&payload)?;
        }
        BodyOperations::from(body).apply(processor)
    }
}
