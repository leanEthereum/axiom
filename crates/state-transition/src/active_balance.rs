//! The total active balance, and the rates it sets for one epoch.

use axiom_types::{ChainConfig, Gwei, Preset, fulu::BeaconState};

/// Total effective balance of the active validators in one epoch.
///
/// Rewards and churn scale with it.
/// It changes only at epoch boundaries, so a block or an epoch transition computes it once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActiveBalance(pub Gwei);

impl ActiveBalance {
    /// The total active balance of a state's current epoch.
    ///
    /// See `get_total_active_balance` in the phase0 beacon chain spec.
    #[must_use]
    pub fn of<P: Preset>(state: &BeaconState<P>) -> Self {
        Self(state.total_active_balance())
    }

    /// Base reward per increment of effective balance.
    ///
    /// It scales with the inverse square root of the total stake.
    /// Issuance then grows with the square root of the stake.
    ///
    /// See `get_base_reward_per_increment` in the Altair beacon chain spec.
    #[must_use]
    pub const fn base_reward_per_increment<P: Preset>(self) -> Gwei {
        Gwei(P::EFFECTIVE_BALANCE_INCREMENT.0 * P::BASE_REWARD_FACTOR / self.0.0.isqrt())
    }

    /// Churn of the epoch in balance, before splitting into its uses.
    ///
    /// See `get_balance_churn_limit` in the Electra beacon chain spec.
    #[must_use]
    pub fn balance_churn_limit<P: Preset>(self, config: &ChainConfig) -> Gwei {
        let churn = config
            .min_per_epoch_churn_limit_electra
            .max(self.0 / config.churn_limit_quotient);
        churn - Gwei(churn.0 % P::EFFECTIVE_BALANCE_INCREMENT.0)
    }

    /// Churn of the epoch reserved for activations and exits.
    ///
    /// See `get_activation_exit_churn_limit` in the Electra beacon chain spec.
    #[must_use]
    pub fn activation_exit_churn_limit<P: Preset>(self, config: &ChainConfig) -> Gwei {
        config
            .max_per_epoch_activation_exit_churn_limit
            .min(self.balance_churn_limit::<P>(config))
    }

    /// Churn of the epoch left for consolidations.
    ///
    /// See `get_consolidation_churn_limit` in the Electra beacon chain spec.
    #[must_use]
    pub fn consolidation_churn_limit<P: Preset>(self, config: &ChainConfig) -> Gwei {
        self.balance_churn_limit::<P>(config) - self.activation_exit_churn_limit::<P>(config)
    }
}
