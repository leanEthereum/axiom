//! Gloas: enshrined proposer-builder separation, see EIP-7732.
//!
//! A block carries a builder's bid, and the payload follows in its own envelope.

pub mod builders;
pub mod ptc;
mod upgrade;

use axiom_types::{
    ChainConfig, Gwei, Preset, ValidatorIndex,
    accessors::{BuilderState, ForkState, LookaheadState},
    gloas::{BeaconBlock, BeaconState, BuilderPendingPayment},
    phase0::BeaconBlockHeader,
};

use crate::{
    ActiveBalance, BlockError, BlockProcessor, EpochProcessor, EpochStep, Fork, PayloadEngine,
    Registry, StateError,
    electra::{
        ElectraEpoch,
        churn::{BalanceChurn, ChurnLimits},
    },
    phase0::{Slashing, SlotRoots},
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
        EpochStep::BuilderPendingPayments,
        EpochStep::EffectiveBalanceUpdates,
        EpochStep::SlashingsReset,
        EpochStep::RandaoMixesReset,
        EpochStep::HistoricalSummariesUpdate,
        EpochStep::ParticipationFlagUpdates,
        EpochStep::SyncCommitteeUpdates,
        EpochStep::ProposerLookahead,
        EpochStep::PtcWindow,
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

    /// Slashes as Electra does, then cancels the slashed proposer's builder payments.
    ///
    /// See `slash_validator` in the Gloas beacon chain spec.
    fn slash_validator(
        registry: &mut Registry<'_, Self>,
        slashed: ValidatorIndex,
        whistleblower: Option<ValidatorIndex>,
    ) -> Result<(), StateError> {
        Slashing {
            slashed,
            whistleblower,
        }
        .apply(registry)?;
        for payment in registry
            .state
            .beacon
            .builder_pending_payments_mut()
            .iter_mut()
        {
            if payment.proposer_index == slashed {
                *payment = BuilderPendingPayment::default();
            }
        }
        Ok(())
    }

    /// Caches the slot's roots, and clears the next slot's payload availability.
    ///
    /// See `process_slot` in the Gloas beacon chain spec.
    fn process_slot(state: &mut Self) {
        SlotRoots::of(state).record(state);
        let next = ((state.slot.0 + 1) % P::SLOTS_PER_HISTORICAL_ROOT) as usize;
        state.execution_payload_availability_mut().set(next, false);
    }

    fn process_epoch_step(
        processor: &mut EpochProcessor<'_, Self>,
        step: EpochStep,
    ) -> Result<(), StateError> {
        match step {
            // Gloas rewrote these steps, or introduced them.
            EpochStep::PendingDeposits
            | EpochStep::BuilderPendingPayments
            | EpochStep::ProposerLookahead
            | EpochStep::PtcWindow => Err(EpochProcessor::<Self>::unsupported(step)),
            _ => ElectraEpoch::run(processor, step),
        }
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

impl<P: Preset> BalanceChurn for BeaconState<P> {
    /// The limits as Gloas sizes them, each use on its own.
    ///
    /// ```text
    /// churn         = max(MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA, total / CHURN_LIMIT_QUOTIENT_GLOAS)
    /// activation    = min(MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS, churn)
    /// exit          = churn
    /// consolidation = total / CONSOLIDATION_CHURN_LIMIT_QUOTIENT
    /// ```
    ///
    /// Each value rounds down to a whole increment.
    /// See `get_activation_churn_limit` and the two limits after it in the Gloas spec.
    fn churn_limits(total_active_balance: ActiveBalance, config: &ChainConfig) -> ChurnLimits {
        let round = |amount: Gwei| amount - Gwei(amount.0 % P::EFFECTIVE_BALANCE_INCREMENT.0);
        let total = total_active_balance.0;
        let churn = round(
            config
                .min_per_epoch_churn_limit_electra
                .max(total / config.churn_limit_quotient_gloas),
        );
        ChurnLimits {
            activation: config.max_per_epoch_activation_churn_limit_gloas.min(churn),
            exit: churn,
            consolidation: round(total / config.consolidation_churn_limit_quotient),
        }
    }
}
