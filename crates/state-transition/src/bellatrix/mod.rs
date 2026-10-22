//! Bellatrix: the merge with the execution layer.
//!
//! It adds the execution payload, and raises the penalties through the fork's constant table.
//! Its other rules are Altair's.

pub mod block;
mod upgrade;

use axiom_types::{
    Preset, ValidatorIndex,
    accessors::ExecutionHeaderState,
    bellatrix::{BeaconBlock, BeaconState},
    phase0::BeaconBlockHeader,
};

use crate::{
    BlockError, BlockProcessor, EpochProcessor, EpochStep, Fork, PayloadEngine, Registry,
    StateError,
    altair::{
        AltairEpoch,
        block::{FlaggedAttestation, ParticipantDeposit},
    },
    bellatrix::block::PayloadExecution,
    phase0::{
        ExitQueue, Slashing, SlotRoots,
        block::{DepositQuota, RandaoReveal},
    },
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
