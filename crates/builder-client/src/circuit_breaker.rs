//! The liveness failsafe: when the chain looks unhealthy, proposers build locally.

use std::collections::BTreeSet;

use axiom_types::{Epoch, Preset, Slot};
use thiserror::Error;

/// The chain's recent history, as the node's fork choice sees it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainHealth {
    /// The slot about to be proposed.
    pub current_slot: Slot,

    /// Slots of the canonical blocks of the last epoch, in any order.
    pub block_slots: BTreeSet<Slot>,

    /// The latest finalized epoch.
    pub finalized_epoch: Epoch,
}

/// Thresholds past which the builder path is closed.
///
/// # Overview
///
/// The validator spec asks every proposer to stop using builders while the chain is unhealthy.
/// The exact signals are left to the client.
/// See the liveness failsafe section of the Bellatrix builder validator spec.
///
/// The danger is correlated failure.
/// When relays misbehave, every proposer relying on them misses its slot at once.
/// Local building has no such shared dependency, so it restores liveness.
///
/// # Invariants
///
/// Each threshold is a most-tolerated value: the breaker trips only strictly above it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CircuitBreaker {
    /// Most missed slots tolerated in a row, right before the current one.
    pub max_consecutive_missed: u64,

    /// Most missed slots tolerated over the last epoch's worth of slots.
    pub max_missed_per_epoch: u64,

    /// Most epochs tolerated between the current epoch and the finalized one.
    pub max_finality_delay: u64,
}

/// Why the breaker closed the builder path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BreakerTrip {
    /// Too many slots in a row have no block.
    #[error("{missed} slots in a row without a block, above the limit {limit}")]
    ConsecutiveMissed {
        /// Missed slots right before the current one.
        missed: u64,
        /// The tolerated count.
        limit: u64,
    },

    /// Too many slots of the last epoch have no block.
    #[error("{missed} of the last {window} slots without a block, above the limit {limit}")]
    MissedInEpoch {
        /// Missed slots in the window.
        missed: u64,
        /// Slots in the window.
        window: u64,
        /// The tolerated count.
        limit: u64,
    },

    /// Finality lags too far behind.
    #[error("finality is {delay} epochs behind, above the limit {limit}")]
    FinalityDelay {
        /// Epochs between the current and the finalized epoch.
        delay: u64,
        /// The tolerated delay.
        limit: u64,
    },
}

impl CircuitBreaker {
    /// Most missed slots tolerated in a row by default.
    ///
    /// At an independent miss rate of 1%, three in a row happen with probability 10^-6.
    /// Three in a row therefore point to a shared cause, such as a relay outage.
    pub const DEFAULT_CONSECUTIVE_MISSED: u64 = 3;

    /// Thresholds no chain can cross, for an operator who always wants builders asked.
    ///
    /// Every threshold is the largest count, and the breaker trips only strictly above one.
    pub const NEVER: Self = Self {
        max_consecutive_missed: u64::MAX,
        max_missed_per_epoch: u64::MAX,
        max_finality_delay: u64::MAX,
    };

    /// The default thresholds of a preset.
    ///
    /// - A quarter of an epoch missed is far above a healthy rate.
    /// - The finality delay limit is the delay past which the inactivity leak starts.
    ///
    /// The leak starts above MIN_EPOCHS_TO_INACTIVITY_PENALTY, see the phase0 beacon chain spec.
    /// A leaking chain needs liveness first, so the breaker trips with it.
    #[must_use]
    pub const fn for_preset<P: Preset>() -> Self {
        Self {
            max_consecutive_missed: Self::DEFAULT_CONSECUTIVE_MISSED,
            max_missed_per_epoch: P::SLOTS_PER_EPOCH / 4,
            max_finality_delay: P::MIN_EPOCHS_TO_INACTIVITY_PENALTY,
        }
    }

    /// Whether the builder path is open for the current slot.
    ///
    /// The window is the epoch's worth of slots before the current one, cut at genesis.
    /// The genesis slot always holds the genesis block, so it never counts as missed.
    ///
    /// # Errors
    ///
    /// Fails with the first threshold crossed: consecutive misses, misses per epoch, then finality.
    pub fn check<P: Preset>(&self, health: &ChainHealth) -> Result<(), BreakerTrip> {
        let current = health.current_slot.0;
        let first = current.saturating_sub(P::SLOTS_PER_EPOCH).max(1);
        let missed = |slot: &u64| !health.block_slots.contains(&Slot(*slot));

        // Count back from the slot before the current one until a block appears.
        let consecutive = (first..current).rev().take_while(missed).count() as u64;
        if consecutive > self.max_consecutive_missed {
            return Err(BreakerTrip::ConsecutiveMissed {
                missed: consecutive,
                limit: self.max_consecutive_missed,
            });
        }

        let in_window = (first..current).filter(missed).count() as u64;
        if in_window > self.max_missed_per_epoch {
            return Err(BreakerTrip::MissedInEpoch {
                missed: in_window,
                window: current.saturating_sub(first),
                limit: self.max_missed_per_epoch,
            });
        }

        // A finalized epoch ahead of the clock means no delay at all.
        let current_epoch = health.current_slot.epoch::<P>();
        let delay = current_epoch.0.saturating_sub(health.finalized_epoch.0);
        if delay > self.max_finality_delay {
            return Err(BreakerTrip::FinalityDelay {
                delay,
                limit: self.max_finality_delay,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Mainnet;

    use super::*;

    /// Health at a slot of epoch 10, with blocks at every slot of the window except the missed ones.
    ///
    /// Finality sits two epochs back, as on a healthy chain.
    fn health(current: u64, missed: &[u64]) -> ChainHealth {
        let block_slots = (current - 32..current)
            .filter(|slot| !missed.contains(slot))
            .map(Slot)
            .collect();
        ChainHealth {
            current_slot: Slot(current),
            block_slots,
            finalized_epoch: Epoch(current / 32 - 2),
        }
    }

    #[test]
    fn the_never_breaker_stays_open_on_a_dead_chain() {
        // Fixture state: slot 1000, no block for a whole epoch, nothing finalized.
        let dead = ChainHealth {
            current_slot: Slot(1000),
            block_slots: BTreeSet::new(),
            finalized_epoch: Epoch(0),
        };
        assert!(CircuitBreaker::NEVER.check::<Mainnet>(&dead).is_ok());
        assert!(
            CircuitBreaker::for_preset::<Mainnet>()
                .check::<Mainnet>(&dead)
                .is_err()
        );
    }

    /// The mainnet defaults: 3 in a row, 8 per epoch, 4 epochs of delay.
    const fn breaker() -> CircuitBreaker {
        CircuitBreaker::for_preset::<Mainnet>()
    }

    #[test]
    fn the_mainnet_defaults() {
        assert_eq!(
            breaker(),
            CircuitBreaker {
                max_consecutive_missed: 3,
                max_missed_per_epoch: 8,
                max_finality_delay: 4,
            }
        );
    }

    #[test]
    fn a_full_window_is_healthy() {
        // Fixture state: slot 330 of epoch 10, every slot from 298 to 329 has a block.
        assert_eq!(breaker().check::<Mainnet>(&health(330, &[])), Ok(()));
    }

    #[test]
    fn three_misses_in_a_row_are_tolerated_and_four_are_not() {
        // Threshold: three missed slots, 327 to 329, sit at the limit.
        assert_eq!(
            breaker().check::<Mainnet>(&health(330, &[327, 328, 329])),
            Ok(())
        );

        // A fourth, 326, crosses it.
        assert_eq!(
            breaker().check::<Mainnet>(&health(330, &[326, 327, 328, 329])),
            Err(BreakerTrip::ConsecutiveMissed {
                missed: 4,
                limit: 3,
            })
        );
    }

    #[test]
    fn a_block_breaks_the_run() {
        // Mutation: 329 has a block, so the three misses before it do not count as a run.
        assert_eq!(
            breaker().check::<Mainnet>(&health(330, &[325, 326, 327, 328])),
            Ok(())
        );
    }

    #[test]
    fn eight_misses_per_epoch_are_tolerated_and_nine_are_not() {
        // Threshold: eight scattered misses, never two in a row.
        let eight = [300, 302, 304, 306, 308, 310, 312, 314];
        assert_eq!(breaker().check::<Mainnet>(&health(330, &eight)), Ok(()));

        // A ninth, 316, crosses it.
        let nine = [300, 302, 304, 306, 308, 310, 312, 314, 316];
        assert_eq!(
            breaker().check::<Mainnet>(&health(330, &nine)),
            Err(BreakerTrip::MissedInEpoch {
                missed: 9,
                window: 32,
                limit: 8,
            })
        );
    }

    #[test]
    fn a_block_older_than_the_window_does_not_count() {
        // Fixture state: blocks only at slots 200 and 329, far before and right before 330.
        // Slot 200 lies outside the 32-slot window, so 31 misses remain.
        let health = ChainHealth {
            current_slot: Slot(330),
            block_slots: BTreeSet::from([Slot(200), Slot(329)]),
            finalized_epoch: Epoch(8),
        };
        assert_eq!(
            breaker().check::<Mainnet>(&health),
            Err(BreakerTrip::MissedInEpoch {
                missed: 31,
                window: 32,
                limit: 8,
            })
        );
    }

    #[test]
    fn four_epochs_of_delay_are_tolerated_and_five_are_not() {
        // Threshold: slot 330 is in epoch 10, so finality at epoch 6 is four behind.
        let mut at_limit = health(330, &[]);
        at_limit.finalized_epoch = Epoch(6);
        assert_eq!(breaker().check::<Mainnet>(&at_limit), Ok(()));

        // Epoch 5 is five behind: the inactivity leak has started.
        let mut beyond = health(330, &[]);
        beyond.finalized_epoch = Epoch(5);
        assert_eq!(
            breaker().check::<Mainnet>(&beyond),
            Err(BreakerTrip::FinalityDelay { delay: 5, limit: 4 })
        );
    }

    #[test]
    fn the_window_stops_at_genesis() {
        // Fixture state: slot 3, with only the genesis block. Slots 1 and 2 are missed.
        // The window holds slots 1 and 2, below every limit.
        let health = ChainHealth {
            current_slot: Slot(3),
            block_slots: BTreeSet::from([Slot(0)]),
            finalized_epoch: Epoch(0),
        };
        assert_eq!(breaker().check::<Mainnet>(&health), Ok(()));

        // At slot 0 the window is empty, and nothing is missed.
        let genesis = ChainHealth::default();
        assert_eq!(breaker().check::<Mainnet>(&genesis), Ok(()));
    }
}
