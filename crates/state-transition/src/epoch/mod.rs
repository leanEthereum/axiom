//! Epoch processing: the accounting run once at the end of every epoch.

mod consolidations;
mod deposits;
mod effective_balance;
mod finality;
mod inactivity;
mod lookahead;
mod participation;
mod registry_updates;
mod rewards;
mod rollover;
mod slashings;

use axiom_types::{ChainConfig, Epoch, Preset};
use consolidations::ConsolidationQueue;
use deposits::DepositQueue;
use effective_balance::Hysteresis;
use finality::Justification;
use inactivity::InactivityUpdates;
use lookahead::Lookahead;
pub use participation::Participation;
use registry_updates::RegistryUpdates;
pub use rewards::Deltas;
use rewards::RewardsAndPenalties;
use rollover::Rollover;
use slashings::CorrelationPenalty;

use crate::{ActiveBalance, State, StateError, registry::Registry};

/// One sub-transition of epoch processing, in spec order.
///
/// Spec tests exercise each one on its own.
/// See `process_epoch` in the Fulu beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EpochStep {
    /// Justify and finalize checkpoints from target votes.
    JustificationAndFinalization,
    /// Raise inactivity scores of absent validators, lower those of present ones.
    InactivityUpdates,
    /// Pay participation rewards and charge penalties.
    RewardsAndPenalties,
    /// Queue, activate, and eject validators.
    RegistryUpdates,
    /// Charge the correlation penalty to slashed validators.
    Slashings,
    /// Clear eth1 data votes at the end of a voting period.
    Eth1DataReset,
    /// Apply queued deposits within the churn.
    PendingDeposits,
    /// Move the stake of consolidated validators.
    PendingConsolidations,
    /// Round balances into effective balances, with hysteresis.
    EffectiveBalanceUpdates,
    /// Clear the next epoch's slashings slot.
    SlashingsReset,
    /// Carry the randao mix into the next epoch's slot.
    RandaoMixesReset,
    /// Summarize a full period of block and state roots.
    HistoricalSummariesUpdate,
    /// Rotate participation flags into the previous epoch.
    ParticipationFlagUpdates,
    /// Rotate sync committees at the end of a period.
    SyncCommitteeUpdates,
    /// Shift the proposer lookahead by one epoch.
    ProposerLookahead,
}

impl EpochStep {
    /// Every step, in the order an epoch transition runs them.
    pub const ALL: [Self; 15] = [
        Self::JustificationAndFinalization,
        Self::InactivityUpdates,
        Self::RewardsAndPenalties,
        Self::RegistryUpdates,
        Self::Slashings,
        Self::Eth1DataReset,
        Self::PendingDeposits,
        Self::PendingConsolidations,
        Self::EffectiveBalanceUpdates,
        Self::SlashingsReset,
        Self::RandaoMixesReset,
        Self::HistoricalSummariesUpdate,
        Self::ParticipationFlagUpdates,
        Self::SyncCommitteeUpdates,
        Self::ProposerLookahead,
    ];

    /// The step's name, as the spec's test vectors spell it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::JustificationAndFinalization => "justification_and_finalization",
            Self::InactivityUpdates => "inactivity_updates",
            Self::RewardsAndPenalties => "rewards_and_penalties",
            Self::RegistryUpdates => "registry_updates",
            Self::Slashings => "slashings",
            Self::Eth1DataReset => "eth1_data_reset",
            Self::PendingDeposits => "pending_deposits",
            Self::PendingConsolidations => "pending_consolidations",
            Self::EffectiveBalanceUpdates => "effective_balance_updates",
            Self::SlashingsReset => "slashings_reset",
            Self::RandaoMixesReset => "randao_mixes_reset",
            Self::HistoricalSummariesUpdate => "historical_summaries_update",
            Self::ParticipationFlagUpdates => "participation_flag_updates",
            Self::SyncCommitteeUpdates => "sync_committee_updates",
            Self::ProposerLookahead => "proposer_lookahead",
        }
    }

    /// The step with a name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|step| step.name() == name)
    }
}

/// Runs the epoch transition on a state at the last slot of an epoch.
///
/// # Overview
///
/// Each step is its own type, built from what the step reads and then applied.
/// Totals that stay fixed through the early steps are computed once, up front.
#[derive(Debug)]
pub struct EpochProcessor<'a, P: Preset> {
    /// The state being transitioned.
    state: &'a mut State<P>,
    /// The chain configuration.
    config: &'a ChainConfig,
    /// The epoch that is ending.
    current_epoch: Epoch,
    /// Total active balance of the ending epoch.
    ///
    /// Only the effective balance step changes it, and no later step reads it.
    total_active_balance: ActiveBalance,
}

impl<'a, P: Preset> EpochProcessor<'a, P> {
    /// A processor for a state at the last slot of an epoch.
    pub fn new(state: &'a mut State<P>, config: &'a ChainConfig) -> Self {
        let current_epoch = state.beacon.current_epoch();
        let total_active_balance = ActiveBalance::of(&state.beacon);
        Self {
            state,
            config,
            current_epoch,
            total_active_balance,
        }
    }

    /// Runs every step in order.
    ///
    /// # Errors
    ///
    /// Fails when the state breaks an invariant.
    pub fn process(&mut self) -> Result<(), StateError> {
        EpochStep::ALL
            .into_iter()
            .try_for_each(|step| self.run(step))
    }

    /// Runs one step.
    ///
    /// # Errors
    ///
    /// Fails when the state breaks an invariant.
    pub fn run(&mut self, step: EpochStep) -> Result<(), StateError> {
        let current = self.current_epoch;
        match step {
            EpochStep::JustificationAndFinalization => {
                Justification::tally(&self.participation()).weigh(&mut self.state.beacon)
            }
            EpochStep::InactivityUpdates => {
                InactivityUpdates::new(&self.participation(), self.config)
                    .apply(&mut self.state.beacon);
                Ok(())
            }
            EpochStep::RewardsAndPenalties => {
                RewardsAndPenalties::new(&self.participation(), self.config).apply(self.state)
            }
            EpochStep::RegistryUpdates => {
                RegistryUpdates::new(&self.state.beacon, self.config).apply(&mut self.registry())
            }
            EpochStep::Slashings => {
                CorrelationPenalty::new(&self.state.beacon, self.total_active_balance)?
                    .apply(self.state)
            }
            EpochStep::Eth1DataReset => {
                Rollover::new(current).reset_eth1_data(&mut self.state.beacon);
                Ok(())
            }
            EpochStep::PendingDeposits => {
                DepositQueue::new(&self.state.beacon, self.config, self.total_active_balance)
                    .apply(&mut self.registry())
            }
            EpochStep::PendingConsolidations => ConsolidationQueue::new(current).apply(self.state),
            EpochStep::EffectiveBalanceUpdates => {
                Hysteresis::new::<P>().apply(&mut self.state.beacon);
                Ok(())
            }
            EpochStep::SlashingsReset => {
                Rollover::new(current).reset_slashings(&mut self.state.beacon);
                Ok(())
            }
            EpochStep::RandaoMixesReset => {
                Rollover::new(current).reset_randao_mix(&mut self.state.beacon);
                Ok(())
            }
            EpochStep::HistoricalSummariesUpdate => {
                Rollover::new(current).update_historical_summaries(&mut self.state.beacon)
            }
            EpochStep::ParticipationFlagUpdates => {
                Rollover::rotate_participation(&mut self.state.beacon)
            }
            EpochStep::SyncCommitteeUpdates => {
                Lookahead::new(current).rotate_sync_committees(self.state)
            }
            EpochStep::ProposerLookahead => {
                Lookahead::new(current).shift_proposers(&mut self.state.beacon)
            }
        }
    }

    /// The ending epoch's participation, as rewards and finality read it.
    #[must_use]
    pub const fn participation(&self) -> Participation<'_, P> {
        Participation::new(&self.state.beacon, self.total_active_balance)
    }

    /// The state's registry, under the ending epoch's total active balance.
    const fn registry(&mut self) -> Registry<'_, P> {
        Registry::new(self.state, self.config, self.total_active_balance)
    }
}
