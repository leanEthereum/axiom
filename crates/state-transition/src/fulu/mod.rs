//! Fulu: peer data availability sampling, and proposers fixed one epoch ahead.
//!
//! See EIP-7594, EIP-7892, and EIP-7917.

pub mod block;
pub mod epoch;
mod upgrade;

use axiom_types::{
    ChainConfig, Preset, ValidatorIndex,
    accessors::LookaheadState,
    fulu::{BeaconBlock, BeaconState},
    phase0::BeaconBlockHeader,
};

use crate::{
    ActiveBalance, BlockError, BlockProcessor, EpochProcessor, EpochStep, Fork, PayloadEngine,
    Registry, StateError,
    electra::{
        ElectraEpoch,
        block::{Exit, PayloadWithdrawals},
        churn::{BalanceChurn, ChurnLimits},
    },
    fulu::{
        block::{PayloadExecution, QueuedDeposit},
        epoch::{DepositQueue, ProposerLookahead},
    },
    phase0::{Slashing, SlotRoots, block::RandaoReveal},
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
        EpochStep::ProposerLookahead,
    ];

    fn block_header(block: &BeaconBlock<P>) -> BeaconBlockHeader {
        block.header()
    }

    fn beacon_proposer_index(state: &Self) -> Result<ValidatorIndex, StateError> {
        Ok(state.lookahead_proposer())
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
        match step {
            EpochStep::PendingDeposits => {
                let mut registry = processor.registry();
                DepositQueue::new(&registry).apply(&mut registry)
            }
            EpochStep::ProposerLookahead => {
                ProposerLookahead::new(processor.current_epoch).shift(&mut *processor.state.beacon)
            }
            _ => ElectraEpoch::run(processor, step),
        }
    }

    /// Runs Fulu's block processing.
    ///
    /// 1. The header.
    /// 2. The withdrawals, by Electra's rule.
    /// 3. The execution payload, by Fulu's rule.
    /// 4. The RANDAO reveal and the eth1 vote, by phase0's rules.
    /// 5. The operations, with no deposits from the old mechanism.
    /// 6. The sync aggregate, by Altair's rule.
    ///
    /// See `process_block` and `process_operations` in the Fulu beacon chain spec.
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

        // Fulu retired deposits from the deposit contract; they arrive as requests instead.
        if !body.deposits.is_empty() {
            return Err(BlockError::DepositsNotAllowed(body.deposits.len()));
        }
        processor.apply_all(&body.proposer_slashings)?;
        processor.apply_all(&body.attester_slashings)?;
        processor.apply_all(&body.attestations)?;
        for exit in &body.voluntary_exits {
            processor.apply(&Exit(exit))?;
        }
        processor.apply_all(&body.bls_to_execution_changes)?;
        for request in &body.execution_requests.deposits {
            processor.apply(&QueuedDeposit(request))?;
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
