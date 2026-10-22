//! Epoch processing: the accounting run once at the end of every epoch.

mod finality;
mod queues;
mod registry;
mod resets;
mod rewards;
mod sync_committee;

use axiom_types::{ChainConfig, Epoch, Gwei, Preset};
pub use rewards::Deltas;

use crate::{State, StateError};

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
/// Totals that stay fixed through the early steps are computed once, up front.
#[derive(Debug)]
pub struct EpochProcessor<'a, P: Preset> {
    /// The state being transitioned.
    state: &'a mut State<P>,
    /// The chain configuration.
    config: &'a ChainConfig,
    /// The epoch that is ending.
    current_epoch: Epoch,
    /// The epoch before it.
    previous_epoch: Epoch,
    /// Total active balance of the ending epoch.
    ///
    /// Only the effective balance step changes it, and no later step reads it.
    total_active_balance: Gwei,
}

impl<'a, P: Preset> EpochProcessor<'a, P> {
    /// A processor for a state at the last slot of an epoch.
    pub fn new(state: &'a mut State<P>, config: &'a ChainConfig) -> Self {
        let beacon = &state.beacon;
        let current_epoch = beacon.current_epoch();
        let previous_epoch = beacon.previous_epoch();
        let total_active_balance = beacon.total_active_balance();
        Self {
            state,
            config,
            current_epoch,
            previous_epoch,
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
        match step {
            EpochStep::JustificationAndFinalization => {
                self.process_justification_and_finalization()
            }
            EpochStep::InactivityUpdates => {
                self.process_inactivity_updates();
                Ok(())
            }
            EpochStep::RewardsAndPenalties => self.process_rewards_and_penalties(),
            EpochStep::RegistryUpdates => self.process_registry_updates(),
            EpochStep::Slashings => self.process_slashings(),
            EpochStep::Eth1DataReset => {
                self.process_eth1_data_reset();
                Ok(())
            }
            EpochStep::PendingDeposits => self.process_pending_deposits(),
            EpochStep::PendingConsolidations => self.process_pending_consolidations(),
            EpochStep::EffectiveBalanceUpdates => {
                self.process_effective_balance_updates();
                Ok(())
            }
            EpochStep::SlashingsReset => {
                self.process_slashings_reset();
                Ok(())
            }
            EpochStep::RandaoMixesReset => {
                self.process_randao_mixes_reset();
                Ok(())
            }
            EpochStep::HistoricalSummariesUpdate => self.process_historical_summaries_update(),
            EpochStep::ParticipationFlagUpdates => self.process_participation_flag_updates(),
            EpochStep::SyncCommitteeUpdates => self.process_sync_committee_updates(),
            EpochStep::ProposerLookahead => self.process_proposer_lookahead(),
        }
    }

    /// Total effective balance of unslashed validators with a flag, in an epoch.
    ///
    /// The epoch is the previous or the current one, whose participation the state keeps.
    fn unslashed_participating_balance(&self, flag: usize, epoch: Epoch) -> Gwei {
        let beacon = &self.state.beacon;
        let participation = if epoch == self.current_epoch {
            &beacon.current_epoch_participation
        } else {
            &beacon.previous_epoch_participation
        };
        let sum: Gwei = beacon
            .validators
            .iter()
            .zip(participation.iter())
            .filter(|(validator, flags)| {
                validator.is_active_at(epoch) && !validator.slashed && flags.has(flag)
            })
            .map(|(validator, _)| validator.effective_balance)
            .sum();
        sum.max(P::EFFECTIVE_BALANCE_INCREMENT)
    }

    /// Whether a validator is an unslashed participant with a flag in the previous epoch.
    fn is_previous_participant(&self, index: usize, flag: usize) -> bool {
        let beacon = &self.state.beacon;
        let validator = &beacon.validators[index];
        validator.is_active_at(self.previous_epoch)
            && !validator.slashed
            && beacon.previous_epoch_participation[index].has(flag)
    }
}
