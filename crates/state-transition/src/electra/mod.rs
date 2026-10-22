//! Electra: larger validators, balance churn, and execution requests.
//!
//! See EIP-6110, EIP-7002, EIP-7251, and EIP-7549.

pub mod block;
pub mod churn;
pub mod compounding;
pub mod deposits;
pub mod epoch;
mod upgrade;

use axiom_types::{
    ChainConfig, Preset, ValidatorIndex,
    accessors::{ParticipationState, SyncCommitteeState, WithdrawalState},
    electra::{BeaconBlock, BeaconState},
    phase0::BeaconBlockHeader,
};

use crate::{
    ActiveBalance, BlockError, BlockProcessor, CachedState, EpochProcessor, EpochStep, Fork,
    PayloadEngine, Registry, StateError,
    altair::AltairEpoch,
    capella::epoch::HistoricalSummaryUpdate,
    electra::{
        block::{BridgeDeposits, Exit, PayloadExecution, PayloadWithdrawals, RequestedDeposit},
        churn::{BalanceChurn, ChurnLimits},
        epoch::{
            ConsolidationQueue, CorrelationPenalty, DepositQueue, Hysteresis, RegistryUpdates,
        },
    },
    phase0::{Slashing, SlotRoots, block::RandaoReveal},
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
        EpochStep::PendingDeposits,
        EpochStep::PendingConsolidations,
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
        Self::initiate_balance_exit(registry, index)
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
        ElectraEpoch::run(processor, step)
    }

    fn attester_rewards(
        state: CachedState<'_, Self>,
        config: &ChainConfig,
    ) -> Result<AttesterRewards, StateError> {
        Ok(AltairEpoch::attester_rewards(state.beacon(), config))
    }

    /// Runs Electra's block processing.
    ///
    /// 1. The header, by phase0's rule.
    /// 2. The withdrawals, by Electra's rule.
    /// 3. The execution payload, by Electra's rule.
    /// 4. The RANDAO reveal and the eth1 vote, by phase0's rules.
    /// 5. The operations, with contract deposits bridged until requests take over.
    /// 6. The sync aggregate, by Altair's rule.
    ///
    /// See `process_block` and `process_operations` in the Electra beacon chain spec.
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

        processor.apply_all(&body.proposer_slashings)?;
        processor.apply_all(&body.attester_slashings)?;
        processor.apply_all(&body.attestations)?;
        // The spec asserts the deposit count first; no earlier operation moves the counts it reads.
        processor.apply(&BridgeDeposits(&body.deposits))?;
        for exit in &body.voluntary_exits {
            processor.apply(&Exit(exit))?;
        }
        processor.apply_all(&body.bls_to_execution_changes)?;
        for request in &body.execution_requests.deposits {
            processor.apply(&RequestedDeposit(request))?;
        }
        processor.apply_all(&body.execution_requests.withdrawals)?;
        processor.apply_all(&body.execution_requests.consolidations)?;

        processor.apply(&body.sync_aggregate)
    }
}

impl<P: Preset> BalanceChurn for BeaconState<P> {
    fn churn_limits(total_active_balance: ActiveBalance, config: &ChainConfig) -> ChurnLimits {
        ChurnLimits::electra::<P>(total_active_balance, config)
    }
}

/// The epoch steps Electra defined, shared by every fork that keeps its queues.
///
/// A fork's epoch processing hands the steps it inherits from Electra to this type.
/// Steps Electra did not rewrite fall through to Altair's.
#[derive(Clone, Copy, Debug)]
pub struct ElectraEpoch;

impl ElectraEpoch {
    /// Runs a step Electra or an earlier fork defined.
    ///
    /// # Errors
    ///
    /// Fails when the state breaks an invariant, or the fork has no rule for the step here.
    pub fn run<S>(processor: &mut EpochProcessor<'_, S>, step: EpochStep) -> Result<(), StateError>
    where
        S: BalanceChurn + ParticipationState + SyncCommitteeState + WithdrawalState,
    {
        let current = processor.current_epoch;
        match step {
            EpochStep::RegistryUpdates => {
                let updates = RegistryUpdates::new(&*processor.state.beacon, processor.config);
                updates.apply(&mut processor.registry())
            }
            EpochStep::Slashings => {
                CorrelationPenalty::new(&*processor.state.beacon, processor.total_active_balance)?
                    .apply(&mut processor.state)
            }
            EpochStep::PendingDeposits => {
                let mut registry = processor.registry();
                DepositQueue::new(&registry).apply(&mut registry)
            }
            EpochStep::PendingConsolidations => {
                ConsolidationQueue::new(current).apply(&mut processor.state)
            }
            EpochStep::EffectiveBalanceUpdates => {
                Hysteresis::new::<S::Preset>().apply(&mut *processor.state.beacon);
                Ok(())
            }
            EpochStep::HistoricalSummariesUpdate => {
                HistoricalSummaryUpdate::new(current).apply(&mut *processor.state.beacon)
            }
            _ => AltairEpoch::run(processor, step),
        }
    }
}
