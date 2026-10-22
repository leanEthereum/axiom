//! Gloas: enshrined proposer-builder separation, see EIP-7732.
//!
//! A block carries a builder's bid, and the payload follows in its own envelope.

pub mod block;
pub mod builders;
mod envelope;
pub mod epoch;
pub mod ptc;
mod upgrade;

use axiom_types::{
    ChainConfig, Gwei, Preset, ValidatorIndex,
    accessors::{BuilderState, CoreState, LookaheadState},
    gloas::{BeaconBlock, BeaconState, BuilderPendingPayment},
    phase0::BeaconBlockHeader,
};
pub use envelope::{EnvelopeError, PayloadEnvelope};

use crate::{
    ActiveBalance, BlockError, BlockProcessor, EpochProcessor, EpochStep, Fork, PayloadEngine,
    Registry, StateError,
    electra::{
        ElectraEpoch,
        block::Exit,
        churn::{BalanceChurn, ChurnLimits},
    },
    fulu::epoch::DepositQueue,
    gloas::{
        block::{BodyLimits, CommittedWithdrawals, IncludedAttestation, ParentPayload},
        epoch::{BuilderPayments, ProposerLookahead},
        ptc::PtcWindow,
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
            // Gloas only changed the churn that sizes the deposit pass, through its churn table.
            EpochStep::PendingDeposits => {
                let mut registry = processor.registry();
                DepositQueue::new(&registry).apply(&mut registry)
            }
            EpochStep::BuilderPendingPayments => {
                BuilderPayments::new::<P>(processor.total_active_balance)?
                    .apply(&mut *processor.state.beacon);
                Ok(())
            }
            EpochStep::ProposerLookahead => {
                ProposerLookahead::new(processor.current_epoch).shift(&mut *processor.state.beacon)
            }
            EpochStep::PtcWindow => PtcWindow::shift(&mut processor.state),
            _ => ElectraEpoch::run(processor, step),
        }
    }

    /// Runs Gloas's block processing.
    ///
    /// 1. The parent's payload, which the block reports as arrived or missing.
    /// 2. The header.
    /// 3. The withdrawals, fixed by the state alone and paid at once.
    /// 4. The bid, which commits to this slot's payload in place of the payload itself.
    /// 5. The RANDAO reveal and the eth1 vote, by phase0's rules.
    /// 6. The operations, within their limits, with attestations judged at the parent's slot.
    /// 7. The payload attestations on the parent's payload.
    /// 8. The sync aggregate, by Altair's rule.
    ///
    /// The payload arrives later in its own envelope, so the engine has nothing to judge here.
    /// See `process_block` and `process_operations` in the Gloas beacon chain spec.
    fn process_block<E: PayloadEngine<P>>(
        processor: &mut BlockProcessor<'_, Self>,
        block: &BeaconBlock<P>,
        header: &BeaconBlockHeader,
        _engine: &E,
    ) -> Result<(), BlockError> {
        let body = &block.body;
        // The parent's slot, read before the header replaces the latest block header.
        let parent_slot = processor.state.beacon().latest_block_header().slot;
        processor.apply(&ParentPayload::of(body))?;
        processor.apply(header)?;
        processor.apply(&CommittedWithdrawals)?;
        processor.apply(&body.signed_execution_payload_bid)?;
        processor.apply(&RandaoReveal(body.randao_reveal))?;
        processor.apply(&body.eth1_data)?;

        // Deposits from the deposit contract stay retired, as in Fulu.
        if !body.deposits.is_empty() {
            return Err(BlockError::DepositsNotAllowed(body.deposits.len()));
        }
        BodyLimits(body).check()?;
        processor.apply_all(&body.proposer_slashings)?;
        processor.apply_all(&body.attester_slashings)?;
        for attestation in &body.attestations {
            processor.apply(&IncludedAttestation::new(attestation, parent_slot))?;
        }
        for exit in &body.voluntary_exits {
            processor.apply(&Exit(exit))?;
        }
        processor.apply_all(&body.bls_to_execution_changes)?;
        // Execution requests left the block: the next block reports them with this payload.
        processor.apply_all(&body.payload_attestations)?;

        processor.apply(&body.sync_aggregate)
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
