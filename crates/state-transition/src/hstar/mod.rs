//! Hstar: the post-quantum validator key registry, see EIP-8450.
//!
//! Blocks carry key registrations, and the parent payload's requests carry owner authorizations.
//! Every other rule is Gloas's.

pub mod block;
mod envelope;
pub mod epoch;
mod upgrade;

use axiom_types::{
    ChainConfig, Preset, ValidatorIndex,
    accessors::{CoreState, LookaheadState},
    gloas,
    hstar::{BeaconBlock, BeaconState},
    phase0::BeaconBlockHeader,
};

use crate::{
    ActiveBalance, BlockError, BlockProcessor, CachedState, EpochProcessor, EpochStep, EpochVotes,
    Fork, PayloadEngine, Registry, StateError,
    altair::AltairEpoch,
    electra::{
        block::Exit,
        churn::{BalanceChurn, ChurnLimits},
    },
    gloas::{
        GloasEpoch,
        block::{CommittedWithdrawals, IncludedAttestation, ParentPayload},
    },
    hstar::{block::BodyLimits, epoch::AuthorizationExpiry},
    phase0::block::RandaoReveal,
    rewards::AttesterRewards,
};

impl<P: Preset> Fork for BeaconState<P> {
    type Block = BeaconBlock<P>;

    const EPOCH_STEPS: &'static [EpochStep] = &[
        EpochStep::JustificationAndFinalization,
        EpochStep::InactivityUpdates,
        EpochStep::RewardsAndPenalties,
        EpochStep::RegistryUpdates,
        EpochStep::PendingPqKeyAuthorizations,
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

    fn slash_validator(
        registry: &mut Registry<'_, Self>,
        slashed: ValidatorIndex,
        whistleblower: Option<ValidatorIndex>,
    ) -> Result<(), StateError> {
        GloasEpoch::slash_validator(registry, slashed, whistleblower)
    }

    fn process_slot(state: &mut Self) {
        GloasEpoch::process_slot(state);
    }

    fn process_epoch_step(
        processor: &mut EpochProcessor<'_, Self>,
        step: EpochStep,
    ) -> Result<(), StateError> {
        match step {
            EpochStep::PendingPqKeyAuthorizations => {
                AuthorizationExpiry::new(processor.current_epoch)
                    .apply(&mut *processor.state.beacon);
                Ok(())
            }
            _ => GloasEpoch::run(processor, step),
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

    /// Runs Hstar's block processing: Gloas's, with key registrations after the operations.
    ///
    /// 1. The parent's payload, whose requests now include key authorizations.
    /// 2. The header.
    /// 3. The withdrawals, fixed by the state alone and paid at once.
    /// 4. The bid, which commits to this slot's payload in place of the payload itself.
    /// 5. The RANDAO reveal and the eth1 vote, by phase0's rules.
    /// 6. The operations, within their limits, with attestations judged at the parent's slot.
    /// 7. The payload attestations on the parent's payload.
    /// 8. The post-quantum key registrations.
    /// 9. The sync aggregate, by Altair's rule.
    ///
    /// See `process_block` in the Gloas beacon chain spec, and `process_operations` in EIP-8450.
    fn process_block<E: PayloadEngine<P>>(
        processor: &mut BlockProcessor<'_, Self>,
        block: &BeaconBlock<P>,
        header: &BeaconBlockHeader,
        _engine: &E,
    ) -> Result<(), BlockError> {
        let body = &block.body;
        let bid = &body.signed_execution_payload_bid.message;
        // The parent's slot, read before the header replaces the latest block header.
        let parent_slot = processor.state.beacon().latest_block_header().slot;
        processor.apply(&ParentPayload::new(
            bid.parent_block_hash,
            &body.parent_execution_requests,
        ))?;
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
        processor.apply_all(&body.payload_attestations)?;

        // Registrations run last among the operations, as EIP-8450 appends them.
        // A validator slashed or exited by an earlier operation can then no longer register.
        processor.apply_all(&body.pq_key_registrations)?;

        processor.apply(&body.sync_aggregate)
    }
}

impl<P: Preset> BalanceChurn for BeaconState<P> {
    /// The limits as Gloas sizes them, which Hstar keeps.
    fn churn_limits(total_active_balance: ActiveBalance, config: &ChainConfig) -> ChurnLimits {
        <gloas::BeaconState<P> as BalanceChurn>::churn_limits(total_active_balance, config)
    }
}
