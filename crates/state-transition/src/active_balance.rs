//! The total active balance, and the rates it sets for one epoch.

use axiom_types::{Gwei, Preset, accessors::CoreState};

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
    pub fn of<S: CoreState + ?Sized>(state: &S) -> Self {
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
}
