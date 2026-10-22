//! Deneb: blobs, see EIP-4844.
//!
//! Deneb also widens the attestation inclusion window, see EIP-7045.
//! It caps activations per epoch, see EIP-7514.
//! It pins the voluntary exit domain to Capella, see EIP-7044.

pub mod block;
mod upgrade;

use axiom_types::{
    ChainConfig, Preset, ValidatorIndex,
    deneb::{BeaconBlock, BeaconState},
    phase0::BeaconBlockHeader,
};

use crate::{
    BlockError, BlockProcessor, CachedState, EpochProcessor, EpochStep, Fork, PayloadEngine,
    Registry, StateError,
    altair::{AltairEpoch, block::ParticipantDeposit},
    capella::{block::PayloadWithdrawals, epoch::HistoricalSummaryUpdate},
    deneb::block::{Exit, PayloadExecution, UnboundedAttestation},
    phase0::{
        ExitQueue, Slashing, SlotRoots,
        block::{DepositQuota, RandaoReveal},
        epoch::RegistryUpdates,
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
            EpochStep::RegistryUpdates => {
                // Deneb caps activations, see EIP-7514.
                let cap = processor.config.max_per_epoch_activation_churn_limit;
                RegistryUpdates::new(&*processor.state.beacon, processor.config)
                    .with_activation_cap(cap)
                    .apply(&mut processor.registry())
            }
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

    /// Runs Deneb's block processing.
    ///
    /// 1. The header.
    /// 2. The withdrawals by Capella's rule, then the execution payload by Deneb's.
    /// 3. The RANDAO reveal and the eth1 vote, by phase0's rules.
    /// 4. The operations, with Deneb's attestations and exits, and Altair's deposits.
    /// 5. The sync aggregate, by Altair's rule.
    ///
    /// See `process_block` and `process_operations` in the Deneb beacon chain spec.
    fn process_block<E: PayloadEngine<P>>(
        processor: &mut BlockProcessor<'_, Self>,
        block: &BeaconBlock<P>,
        header: &BeaconBlockHeader,
        engine: &E,
    ) -> Result<(), BlockError> {
        let body = &block.body;
        processor.apply(header)?;
        processor.apply(&PayloadWithdrawals(&body.execution_payload.withdrawals))?;
        processor.apply(&PayloadExecution::new(body, engine))?;
        processor.apply(&RandaoReveal(body.randao_reveal))?;
        processor.apply(&body.eth1_data)?;

        DepositQuota::of(processor.state.beacon()).check(body.deposits.len())?;
        processor.apply_all(&body.proposer_slashings)?;
        processor.apply_all(&body.attester_slashings)?;
        for attestation in &body.attestations {
            processor.apply(&UnboundedAttestation(attestation))?;
        }
        for deposit in &body.deposits {
            processor.apply(&ParticipantDeposit(deposit))?;
        }
        for exit in &body.voluntary_exits {
            processor.apply(&Exit(exit))?;
        }
        processor.apply_all(&body.bls_to_execution_changes)?;

        processor.apply(&body.sync_aggregate)
    }
}
