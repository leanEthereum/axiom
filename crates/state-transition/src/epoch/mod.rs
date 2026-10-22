//! Epoch processing: the accounting run once at the end of every epoch.

use axiom_types::{self, ChainConfig, Epoch};

use crate::{ActiveBalance, CachedState, Fork, Registry, StateError};

/// One sub-transition of epoch processing, across every fork.
///
/// Each fork runs a subset, in its own order, and spec tests exercise each one on its own.
/// See `process_epoch` in each fork's beacon chain spec.
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
    /// Settle the builder payments whose bids reached their quorum.
    BuilderPendingPayments,
    /// Round balances into effective balances, with hysteresis.
    EffectiveBalanceUpdates,
    /// Clear the next epoch's slashings slot.
    SlashingsReset,
    /// Carry the randao mix into the next epoch's slot.
    RandaoMixesReset,
    /// Accumulate a full period of block and state roots, before Capella.
    HistoricalRootsUpdate,
    /// Summarize a full period of block and state roots, from Capella on.
    HistoricalSummariesUpdate,
    /// Rotate pending attestations into the previous epoch, before Altair.
    ParticipationRecordUpdates,
    /// Rotate participation flags into the previous epoch, from Altair on.
    ParticipationFlagUpdates,
    /// Rotate sync committees at the end of a period.
    SyncCommitteeUpdates,
    /// Shift the proposer lookahead by one epoch.
    ProposerLookahead,
    /// Shift the payload timeliness committees by one epoch.
    PtcWindow,
}

impl EpochStep {
    /// Every step of every fork.
    pub const ALL: [Self; 19] = [
        Self::JustificationAndFinalization,
        Self::InactivityUpdates,
        Self::RewardsAndPenalties,
        Self::RegistryUpdates,
        Self::Slashings,
        Self::Eth1DataReset,
        Self::PendingDeposits,
        Self::PendingConsolidations,
        Self::BuilderPendingPayments,
        Self::EffectiveBalanceUpdates,
        Self::SlashingsReset,
        Self::RandaoMixesReset,
        Self::HistoricalRootsUpdate,
        Self::HistoricalSummariesUpdate,
        Self::ParticipationRecordUpdates,
        Self::ParticipationFlagUpdates,
        Self::SyncCommitteeUpdates,
        Self::ProposerLookahead,
        Self::PtcWindow,
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
            Self::BuilderPendingPayments => "builder_pending_payments",
            Self::EffectiveBalanceUpdates => "effective_balance_updates",
            Self::SlashingsReset => "slashings_reset",
            Self::RandaoMixesReset => "randao_mixes_reset",
            Self::HistoricalRootsUpdate => "historical_roots_update",
            Self::HistoricalSummariesUpdate => "historical_summaries_update",
            Self::ParticipationRecordUpdates => "participation_record_updates",
            Self::ParticipationFlagUpdates => "participation_flag_updates",
            Self::SyncCommitteeUpdates => "sync_committee_updates",
            Self::ProposerLookahead => "proposer_lookahead",
            Self::PtcWindow => "ptc_window",
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
/// The processor holds what every fork's epoch processing shares.
/// Each step is its own type, built from what the step reads and then applied.
/// Totals that stay fixed through the early steps are computed once, up front.
#[derive(Debug)]
pub struct EpochProcessor<'a, S> {
    /// The state being transitioned, with its caches.
    pub(crate) state: CachedState<'a, S>,
    /// The chain configuration.
    pub(crate) config: &'a ChainConfig,
    /// The epoch that is ending.
    pub(crate) current_epoch: Epoch,
    /// Total active balance of the ending epoch.
    ///
    /// Only the effective balance step changes it, and no later step reads it.
    pub(crate) total_active_balance: ActiveBalance,
}

impl<'a, S: Fork> EpochProcessor<'a, S> {
    /// A processor for a state at the last slot of an epoch.
    #[must_use]
    pub fn new(state: CachedState<'a, S>, config: &'a ChainConfig) -> Self {
        let current_epoch = state.beacon().current_epoch();
        let total_active_balance = ActiveBalance::of(state.beacon());
        Self {
            state,
            config,
            current_epoch,
            total_active_balance,
        }
    }

    /// Runs every step of the fork, in order.
    ///
    /// # Errors
    ///
    /// Fails when the state breaks an invariant.
    pub fn process(&mut self) -> Result<(), StateError> {
        S::EPOCH_STEPS
            .iter()
            .try_for_each(|step| S::process_epoch_step(self, *step))
    }

    /// Runs one step.
    ///
    /// # Errors
    ///
    /// Fails when the step is not one of the fork's, or the state breaks an invariant.
    pub fn run(&mut self, step: EpochStep) -> Result<(), StateError> {
        if !S::EPOCH_STEPS.contains(&step) {
            return Err(Self::unsupported(step));
        }
        S::process_epoch_step(self, step)
    }

    /// The state being transitioned, with its caches.
    pub const fn state(&mut self) -> &mut CachedState<'a, S> {
        &mut self.state
    }

    /// The epoch that is ending.
    #[must_use]
    pub const fn current_epoch(&self) -> Epoch {
        self.current_epoch
    }

    /// Total active balance of the ending epoch.
    #[must_use]
    pub const fn total_active_balance(&self) -> ActiveBalance {
        self.total_active_balance
    }

    /// The state's registry, under the ending epoch's total active balance.
    pub const fn registry(&mut self) -> Registry<'_, S> {
        Registry::new(
            self.state.reborrow(),
            self.config,
            self.total_active_balance,
        )
    }

    /// The error for a step this fork has no rule for.
    ///
    /// A step outside the fork's list is foreign to it.
    /// A step on the list without a rule is one whose fork code is not written yet.
    #[must_use]
    pub fn unsupported(step: EpochStep) -> StateError {
        if S::EPOCH_STEPS.contains(&step) {
            StateError::RulesMissing {
                fork: S::FORK,
                rules: step.name(),
            }
        } else {
            StateError::StepNotInFork {
                step: step.name(),
                fork: S::FORK,
            }
        }
    }
}
