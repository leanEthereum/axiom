//! Balance churn: stake that enters, leaves, or merges at a bounded rate per epoch.

use axiom_types::{ChainConfig, Epoch, Gwei, Preset, ValidatorIndex, accessors::PendingQueueState};

use crate::{ActiveBalance, Fork, Registry, StateError};

/// The churn of one epoch in balance, split into its uses.
///
/// Electra splits one balance churn in two: activations and exits, then consolidations.
/// Gloas sizes each use on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChurnLimits {
    /// Balance the deposit queue may activate per epoch.
    pub activation: Gwei,
    /// Balance the exit queue may release per epoch.
    pub exit: Gwei,
    /// Balance the consolidation queue may move per epoch.
    pub consolidation: Gwei,
}

impl ChurnLimits {
    /// The limits as Electra derives them from the total active balance.
    ///
    /// ```text
    /// balance churn       = max(MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA, total / CHURN_LIMIT_QUOTIENT)
    /// activation and exit = min(MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT, balance churn)
    /// consolidation       = balance churn - activation and exit
    /// ```
    ///
    /// Each value rounds down to a whole increment.
    /// See `get_balance_churn_limit` and the two limits after it in the Electra spec.
    #[must_use]
    pub fn electra<P: Preset>(total_active_balance: ActiveBalance, config: &ChainConfig) -> Self {
        let churn = config
            .min_per_epoch_churn_limit_electra
            .max(total_active_balance.0 / config.churn_limit_quotient);
        let balance_churn = churn - Gwei(churn.0 % P::EFFECTIVE_BALANCE_INCREMENT.0);
        let activation_exit = config
            .max_per_epoch_activation_exit_churn_limit
            .min(balance_churn);
        Self {
            activation: activation_exit,
            exit: activation_exit,
            consolidation: balance_churn - activation_exit,
        }
    }
}

/// The tail of one churn queue: its last scheduled epoch and the balance that epoch can still take.
///
/// Exits and consolidations each keep such a tail in the state.
/// See `compute_exit_epoch_and_update_churn` in the Electra beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChurnQueue {
    /// The latest epoch anything in the queue is scheduled for.
    pub earliest_epoch: Epoch,
    /// Balance that epoch can still admit.
    pub balance_to_consume: Gwei,
}

impl ChurnQueue {
    /// Schedules a balance and returns the epoch it lands in, consuming that churn.
    ///
    /// # Arguments
    ///
    /// The balance to schedule, the churn each epoch admits, and the earliest epoch allowed.
    ///
    /// # Algorithm
    ///
    /// Entries queue behind each other, each epoch admitting one epoch's churn of balance.
    ///
    /// ```text
    /// churn = 128 ETH per epoch, 40 ETH left in epoch 10, exit of 200 ETH
    ///
    /// 200 - 40 = 160 more ETH, needing ceil(160 / 128) = 2 more epochs
    /// the exit lands in epoch 12, leaving 40 + 256 - 200 = 96 ETH there
    /// ```
    pub fn schedule(&mut self, balance: Gwei, per_epoch_churn: Gwei, earliest: Epoch) -> Epoch {
        let mut epoch = self.earliest_epoch.max(earliest);

        // A later epoch than the queue's tail starts with a full churn budget.
        let mut to_consume = if self.earliest_epoch < epoch {
            per_epoch_churn
        } else {
            self.balance_to_consume
        };

        if balance > to_consume {
            let remaining = balance - to_consume;
            let additional_epochs = (remaining.0 - 1) / per_epoch_churn.0 + 1;
            epoch += additional_epochs;
            to_consume += per_epoch_churn * additional_epochs;
        }

        self.balance_to_consume = to_consume - balance;
        self.earliest_epoch = epoch;
        epoch
    }
}

/// A state whose exits and consolidations draw on a churn of balance, from Electra on.
///
/// The queue rules are Electra's.
/// Gloas changed only how the limits are sized, so a fork supplies just its limits.
pub trait BalanceChurn: Fork + PendingQueueState {
    /// The epoch's churn limits under a total active balance.
    fn churn_limits(total_active_balance: ActiveBalance, config: &ChainConfig) -> ChurnLimits;

    /// Earliest epoch an exit of some balance fits in, consuming that churn.
    ///
    /// See `compute_exit_epoch_and_update_churn` in the Electra beacon chain spec.
    fn exit_epoch(registry: &mut Registry<'_, Self>, balance: Gwei) -> Epoch {
        let limits = Self::churn_limits(registry.total_active_balance, registry.config);
        let state = &mut *registry.state.beacon;
        let earliest = state
            .current_epoch()
            .activation_exit_epoch::<Self::Preset>();
        let mut queue = ChurnQueue {
            earliest_epoch: state.earliest_exit_epoch(),
            balance_to_consume: state.exit_balance_to_consume(),
        };
        let epoch = queue.schedule(balance, limits.exit, earliest);
        *state.earliest_exit_epoch_mut() = queue.earliest_epoch;
        *state.exit_balance_to_consume_mut() = queue.balance_to_consume;
        epoch
    }

    /// Earliest epoch a consolidation of some balance fits in, consuming that churn.
    ///
    /// The same queue as exits, with the consolidation share of the churn.
    /// See `compute_consolidation_epoch_and_update_churn` in the Electra beacon chain spec.
    fn consolidation_epoch(registry: &mut Registry<'_, Self>, balance: Gwei) -> Epoch {
        let limits = Self::churn_limits(registry.total_active_balance, registry.config);
        let state = &mut *registry.state.beacon;
        let earliest = state
            .current_epoch()
            .activation_exit_epoch::<Self::Preset>();
        let mut queue = ChurnQueue {
            earliest_epoch: state.earliest_consolidation_epoch(),
            balance_to_consume: state.consolidation_balance_to_consume(),
        };
        let epoch = queue.schedule(balance, limits.consolidation, earliest);
        *state.earliest_consolidation_epoch_mut() = queue.earliest_epoch;
        *state.consolidation_balance_to_consume_mut() = queue.balance_to_consume;
        epoch
    }

    /// Schedules an exit for the earliest epoch the exit churn allows.
    ///
    /// A validator already exiting keeps its schedule.
    /// See `initiate_validator_exit` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist or an epoch overflows.
    fn initiate_balance_exit(
        registry: &mut Registry<'_, Self>,
        index: ValidatorIndex,
    ) -> Result<(), StateError> {
        let validators = registry.state.beacon().validators();
        let validator = validators
            .get(index.as_usize())
            .ok_or(StateError::UnknownValidator {
                index,
                registry_size: validators.len(),
            })?;
        if validator.exit_epoch != Epoch::FAR_FUTURE {
            return Ok(());
        }

        let effective_balance = validator.effective_balance;
        let exit_epoch = Self::exit_epoch(registry, effective_balance);
        let withdrawable_epoch = registry.withdrawable_epoch(exit_epoch)?;
        let validator = &mut registry.state.beacon.validators_mut()[index.as_usize()];
        validator.exit_epoch = exit_epoch;
        validator.withdrawable_epoch = withdrawable_epoch;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;

    use super::*;

    #[test]
    fn an_exit_larger_than_the_tail_spills_into_later_epochs() {
        // Fixture state: 40 ETH left in epoch 10, a churn of 128 ETH per epoch.
        let mut queue = ChurnQueue {
            earliest_epoch: Epoch(10),
            balance_to_consume: Gwei(40_000_000_000),
        };

        // 200 ETH needs ceil(160 / 128) = 2 more epochs, leaving 96 ETH in epoch 12.
        let epoch = queue.schedule(Gwei(200_000_000_000), Gwei(128_000_000_000), Epoch(5));
        assert_eq!(epoch, Epoch(12));
        assert_eq!(
            queue,
            ChurnQueue {
                earliest_epoch: Epoch(12),
                balance_to_consume: Gwei(96_000_000_000),
            }
        );
    }

    #[test]
    fn electra_limits_split_one_balance_churn() {
        // Minimal configuration: floor 64 ETH, quotient 32, activation and exit cap 128 ETH.
        let config = ChainConfig::minimal();

        // 8192 ETH active: 8192 / 32 = 256 ETH of churn, capped at 128 for activations and exits.
        let limits =
            ChurnLimits::electra::<Minimal>(ActiveBalance(Gwei(8_192_000_000_000)), &config);
        assert_eq!(
            limits,
            ChurnLimits {
                activation: Gwei(128_000_000_000),
                exit: Gwei(128_000_000_000),
                consolidation: Gwei(128_000_000_000),
            }
        );

        // 1024 ETH active: 32 ETH is below the 64 ETH floor, which leaves nothing to consolidate.
        let limits =
            ChurnLimits::electra::<Minimal>(ActiveBalance(Gwei(1_024_000_000_000)), &config);
        assert_eq!(limits.exit, Gwei(64_000_000_000));
        assert_eq!(limits.consolidation, Gwei::ZERO);
    }
}
