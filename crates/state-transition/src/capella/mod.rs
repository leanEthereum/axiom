//! Capella: withdrawals, credential changes, and historical summaries.

pub mod block;
pub mod epoch;
mod upgrade;

use axiom_types::{
    ChainConfig, Preset, ValidatorIndex,
    capella::{BeaconBlock, BeaconState},
    phase0::BeaconBlockHeader,
};

use crate::{
    BlockError, BlockProcessor, CachedState, EpochProcessor, EpochStep, Fork, PayloadEngine,
    Registry, StateError,
    altair::{
        AltairEpoch,
        block::{FlaggedAttestation, ParticipantDeposit},
    },
    capella::{
        block::{PayloadExecution, PayloadWithdrawals},
        epoch::HistoricalSummaryUpdate,
    },
    phase0::{
        ExitQueue, Slashing, SlotRoots,
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
        processor.apply(&PayloadWithdrawals(&payload.withdrawals))?;
        processor.apply(&PayloadExecution::new(payload, engine))?;
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
        processor.apply_all(&body.bls_to_execution_changes)?;

        processor.apply(&body.sync_aggregate)
    }
}
