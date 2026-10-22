//! Weak subjectivity: the checkpoint an operator trusts, and how long a state stays safe to start from.

use std::{fmt, str::FromStr};

use axiom_json::Data;
use axiom_state_transition::{ActiveBalance, electra::churn::BalanceChurn, phase0::ExitQueue};
use axiom_types::{
    ChainConfig, Epoch, Gwei, Preset, Root, Slot, accessors::CoreState, combined, electra, fulu,
    gloas, phase0::Checkpoint,
};
use thiserror::Error;

/// One ether in gwei, so the period's products stay within 64 bits.
///
/// See `ETH_TO_GWEI` in the phase0 weak subjectivity guide.
const ETH_TO_GWEI: u64 = 1_000_000_000;

/// The tolerated loss of the one-third safety margin, in percent.
///
/// See `SAFETY_DECAY` in the phase0 weak subjectivity guide.
const SAFETY_DECAY: u64 = 10;

/// A checkpoint the operator trusts, given as a block root and an epoch.
///
/// # Overview
///
/// Validators that exited long ago can sign a conflicting history without penalty.
/// That is the long-range attack: such a chain looks valid to a node syncing from scratch.
/// A recent trusted checkpoint rules it out, since an honest chain must pass through it.
///
/// The check has two halves, as the phase0 weak subjectivity guide sets out:
///
/// - Before the node finalizes the checkpoint's epoch, sync must pass through the checkpoint.
/// - Once it has, the canonical block at that epoch must be the checkpoint's block.
///
/// A failure is critical: the node is on another chain than the one its operator trusts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WeakSubjectivity(pub Checkpoint);

impl WeakSubjectivity {
    /// Checks the checkpoint against a state that recorded its epoch's block.
    ///
    /// The state proves the block at the start of each recent epoch through its block roots.
    ///
    /// # Returns
    ///
    /// Whether the state settled the check; it cannot for an epoch outside its ring buffer.
    ///
    /// # Errors
    ///
    /// Fails when the state's block at the epoch is another block.
    pub fn check_state<P: Preset>(
        self,
        state: &combined::BeaconState<P>,
    ) -> Result<bool, WeakSubjectivityError> {
        match state.block_root(self.0.epoch) {
            Some(root) => self.check_block(root).map(|()| true),
            None => Ok(false),
        }
    }

    /// Checks the canonical block at the start of the checkpoint's epoch.
    ///
    /// An empty first slot leaves the latest earlier block canonical there, as the spec's lookup does.
    ///
    /// # Errors
    ///
    /// Fails when the canonical block is another block.
    pub fn check_block(self, canonical: Root) -> Result<(), WeakSubjectivityError> {
        if canonical == self.0.root {
            Ok(())
        } else {
            Err(WeakSubjectivityError::Conflict {
                epoch: self.0.epoch,
                expected: self.0.root,
                actual: canonical,
            })
        }
    }

    /// The slot whose canonical block settles the check.
    #[must_use]
    pub const fn slot<P: Preset>(self) -> Slot {
        self.0.epoch.start_slot::<P>()
    }

    /// Epochs after a state's epoch that a node may still safely start from it.
    ///
    /// Phase0 to Deneb bound the churn in validators, Electra and Fulu in balance.
    /// Gloas weighs each kind of churn on its own.
    /// See `compute_weak_subjectivity_period` in each fork's weak subjectivity guide.
    #[must_use]
    pub fn period<P: Preset>(state: &combined::BeaconState<P>, config: &ChainConfig) -> u64 {
        let base = config.min_validator_withdrawability_delay;
        let churn_epochs = match state {
            combined::BeaconState::Phase0(_)
            | combined::BeaconState::Altair(_)
            | combined::BeaconState::Bellatrix(_)
            | combined::BeaconState::Capella(_)
            | combined::BeaconState::Deneb(_) => Self::validator_churn_epochs(state, config),
            combined::BeaconState::Electra(_) => Self::balance_churn_epochs::<
                electra::BeaconState<P>,
            >(ActiveBalance::of(state), config),
            combined::BeaconState::Fulu(_) => {
                Self::balance_churn_epochs::<fulu::BeaconState<P>>(ActiveBalance::of(state), config)
            }
            combined::BeaconState::Gloas(_) => {
                Self::split_churn_epochs::<P>(ActiveBalance::of(state), config)
            }
        };
        base + churn_epochs
    }

    /// Whether a state is recent enough to start from at the current epoch.
    ///
    /// See `is_within_weak_subjectivity_period` in the phase0 weak subjectivity guide.
    #[must_use]
    pub fn is_within_period<P: Preset>(
        state: &combined::BeaconState<P>,
        config: &ChainConfig,
        current: Epoch,
    ) -> bool {
        current.0
            <= state
                .current_epoch()
                .0
                .saturating_add(Self::period(state, config))
    }

    /// The churn part of the period while churn counts validators.
    fn validator_churn_epochs<P: Preset>(
        state: &combined::BeaconState<P>,
        config: &ChainConfig,
    ) -> u64 {
        let epoch = state.current_epoch();
        let active = state
            .validators()
            .iter()
            .filter(|validator| validator.is_active_at(epoch))
            .count() as u64;
        // An empty active set has no stake to attack with, and the average would divide by zero.
        if active == 0 {
            return 0;
        }
        ValidatorChurn {
            active,
            average: state.total_active_balance().0 / active / ETH_TO_GWEI,
            maximum: P::MAX_EFFECTIVE_BALANCE.0 / ETH_TO_GWEI,
            churn: ExitQueue::churn_limit(state, config),
            top_ups: P::MAX_DEPOSITS * P::SLOTS_PER_EPOCH,
        }
        .epochs()
    }

    /// The churn part of the period while churn counts balance, Electra and Fulu.
    ///
    /// ```text
    /// SAFETY_DECAY * total active balance / (2 * balance churn limit * 100)
    /// ```
    fn balance_churn_epochs<S: BalanceChurn>(total: ActiveBalance, config: &ChainConfig) -> u64 {
        let limits = S::churn_limits(total, config);
        // The balance churn splits into activations and exits, then consolidations.
        Self::balance_epochs(total.0, limits.exit + limits.consolidation)
    }

    /// The churn part of the period in Gloas, which sizes each churn on its own.
    ///
    /// ```text
    /// delta = 2 * exit churn / 3 + activation churn / 3 + consolidation churn
    /// SAFETY_DECAY * total active balance / (2 * delta * 100)
    /// ```
    fn split_churn_epochs<P: Preset>(total: ActiveBalance, config: &ChainConfig) -> u64 {
        let limits = <gloas::BeaconState<P> as BalanceChurn>::churn_limits(total, config);
        let delta = Gwei(2 * limits.exit.0 / 3 + limits.activation.0 / 3 + limits.consolidation.0);
        Self::balance_epochs(total.0, delta)
    }

    /// Epochs a balance churn takes to move the safety decay's share of the stake.
    const fn balance_epochs(total: Gwei, delta: Gwei) -> u64 {
        // The churn is at least the minimum churn limit, never zero under a valid configuration.
        // A zero leaves the base period alone rather than dividing by it.
        if delta.0 == 0 {
            return 0;
        }
        // Total stake stays far below 2^60 gwei, so ten times it fits in 64 bits.
        SAFETY_DECAY * total.0 / (2 * delta.0 * 100)
    }
}

/// The inputs of the period while churn counts validators, balances in whole ether.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ValidatorChurn {
    /// Active validators, N.
    active: u64,
    /// Average active balance, t.
    average: u64,
    /// Maximum effective balance, T.
    maximum: u64,
    /// Validators the churn admits per epoch, delta.
    churn: u64,
    /// Deposits a full epoch of blocks can carry, Delta.
    top_ups: u64,
}

impl ValidatorChurn {
    /// The churn part of the phase0 period.
    ///
    /// ```text
    /// D = SAFETY_DECAY
    /// if t (200 + 12 D) > T (200 + 3 D):
    ///     max(N (t (200 + 12 D) - T (200 + 3 D)) / (600 delta (2 t + T)), N (200 + 3 D) / (600 Delta))
    /// else:
    ///     3 N D t / (200 Delta (T - t))
    /// ```
    const fn epochs(self) -> u64 {
        let Self {
            active: n,
            average: t,
            maximum: max,
            churn: delta,
            top_ups,
        } = self;
        let d = SAFETY_DECAY;
        if t * (200 + 12 * d) > max * (200 + 3 * d) {
            let churn =
                n * (t * (200 + 12 * d) - max * (200 + 3 * d)) / (600 * delta * (2 * t + max));
            let balance_top_ups = n * (200 + 3 * d) / (600 * top_ups);
            if churn > balance_top_ups {
                churn
            } else {
                balance_top_ups
            }
        } else {
            3 * n * d * t / (200 * top_ups * (max - t))
        }
    }
}

impl FromStr for WeakSubjectivity {
    type Err = WeakSubjectivityError;

    /// Parses the guide's format: a hex block root, a colon, and a decimal epoch.
    ///
    /// See the weak subjectivity sync procedure in the phase0 weak subjectivity guide.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || WeakSubjectivityError::Malformed(text.to_owned());
        let (root, epoch) = text.split_once(':').ok_or_else(invalid)?;
        let root = <[u8; 32]>::from_data(root).map_err(|_| invalid())?;
        let epoch = epoch.parse().map_err(|_| invalid())?;
        Ok(Self(Checkpoint {
            epoch: Epoch(epoch),
            root: Root(root),
        }))
    }
}

impl fmt::Display for WeakSubjectivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.0.root, self.0.epoch)
    }
}

/// A weak subjectivity check that failed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum WeakSubjectivityError {
    /// The checkpoint is not a hex root, a colon, and an epoch.
    #[error("weak subjectivity checkpoint {0:?} is not in the form 0x<block root>:<epoch>")]
    Malformed(String),
    /// The chain's block at the checkpoint's epoch is another block.
    #[error("the chain's block at epoch {epoch} is {actual}, not the trusted {expected}")]
    Conflict {
        /// The checkpoint's epoch.
        epoch: Epoch,
        /// The trusted block root.
        expected: Root,
        /// The chain's block root there.
        actual: Root,
    },
    /// A state to start from is older than its weak subjectivity period allows.
    #[error(
        "state of epoch {state_epoch} is stale: its period of {period} epochs ended before epoch {current}"
    )]
    Stale {
        /// The state's epoch.
        state_epoch: Epoch,
        /// The state's weak subjectivity period, in epochs.
        period: u64,
        /// The current epoch.
        current: Epoch,
    },
}

#[cfg(test)]
mod tests {
    use axiom_types::Mainnet;

    use super::*;

    /// A total active balance of a whole number of ether.
    const fn ether(amount: u64) -> ActiveBalance {
        ActiveBalance(Gwei(amount * ETH_TO_GWEI))
    }

    #[test]
    fn the_phase0_period_matches_the_guide_table() {
        // The guide's rows at a 32 ETH average balance, under mainnet's churn and deposit limits.
        //
        //     validators   period
        //     32768        665
        //     65536        1075
        //     131072       1894
        //     262144       3532
        let config = ChainConfig::mainnet();
        let rows = [
            (32_768, 665),
            (65_536, 1075),
            (131_072, 1894),
            (262_144, 3532),
        ];
        for (active, period) in rows {
            let churn = ValidatorChurn {
                active,
                average: 32,
                maximum: 32,
                // The validator churn limit: max(4, N / 65536).
                churn: (active / config.churn_limit_quotient).max(config.min_per_epoch_churn_limit),
                top_ups: Mainnet::MAX_DEPOSITS * Mainnet::SLOTS_PER_EPOCH,
            };
            assert_eq!(
                config.min_validator_withdrawability_delay + churn.epochs(),
                period,
                "{active}"
            );
        }
    }

    #[test]
    fn a_low_average_balance_takes_the_top_up_bound() {
        // Fixture state: 32768 validators averaging 20 ETH, below the 32 ETH maximum.
        //
        //     t (200 + 12 D) = 20 * 320 = 6400
        //     T (200 + 3 D)  = 32 * 230 = 7360
        //
        // The first is smaller, so the bound is 3 N D t / (200 Delta (T - t)).
        //
        //     3 * 32768 * 10 * 20 / (200 * 512 * 12) = 19660800 / 1228800 = 16
        let churn = ValidatorChurn {
            active: 32_768,
            average: 20,
            maximum: 32,
            churn: 4,
            top_ups: 512,
        };
        assert_eq!(churn.epochs(), 16);

        // The guide's 28 ETH rows sit above the threshold: 28 * 320 = 8960.
        //
        //     validators   period
        //     32768        504
        //     65536        752
        for (active, period) in [(32_768, 504), (65_536, 752)] {
            let churn = ValidatorChurn {
                active,
                average: 28,
                ..churn
            };
            assert_eq!(256 + churn.epochs(), period, "{active}");
        }
    }

    #[test]
    fn the_electra_period_matches_the_guide_table() {
        let config = ChainConfig::mainnet();
        let rows = [
            (1_048_576, 665),
            (2_097_152, 1075),
            (4_194_304, 1894),
            (8_388_608, 3532),
            (16_777_216, 3532),
            (33_554_432, 3532),
        ];
        for (total, period) in rows {
            let epochs = WeakSubjectivity::balance_churn_epochs::<electra::BeaconState<Mainnet>>(
                ether(total),
                &config,
            );
            assert_eq!(256 + epochs, period, "{total}");
        }
    }

    #[test]
    fn the_gloas_period_matches_the_guide_table() {
        let config = ChainConfig::mainnet();
        let rows = [
            (1_048_576, 620),
            (2_097_152, 911),
            (4_194_304, 1348),
            (8_388_608, 1348),
            (16_777_216, 1484),
            (33_554_432, 1566),
            (67_108_864, 1611),
            (134_217_728, 1635),
        ];
        for (total, period) in rows {
            let epochs = WeakSubjectivity::split_churn_epochs::<Mainnet>(ether(total), &config);
            assert_eq!(256 + epochs, period, "{total}");
        }
    }

    #[test]
    fn a_checkpoint_parses_from_the_guide_format_and_prints_back() {
        let text = "0x8584188b86a9296932785cc2827b925f9deebacce6d72ad8d53171fa046b43d9:9544";
        let checkpoint: WeakSubjectivity = text.parse().unwrap();

        assert_eq!(checkpoint.0.epoch, Epoch(9544));
        assert_eq!(checkpoint.0.root.0[..2], [0x85, 0x84]);
        assert_eq!(checkpoint.to_string(), text);
        let root = "0x8584188b86a9296932785cc2827b925f9deebacce6d72ad8d53171fa046b43d9";
        for malformed in [
            "0x8584:9544".to_owned(),
            "9544".to_owned(),
            format!("{root}:"),
            format!("{root}:-1"),
        ] {
            assert_eq!(
                malformed.parse::<WeakSubjectivity>(),
                Err(WeakSubjectivityError::Malformed(malformed.clone()))
            );
        }
    }

    #[test]
    fn a_canonical_block_must_be_the_trusted_one() {
        let checkpoint = WeakSubjectivity(Checkpoint {
            epoch: Epoch(3),
            root: Root([1; 32]),
        });

        assert_eq!(checkpoint.check_block(Root([1; 32])), Ok(()));
        assert_eq!(
            checkpoint.check_block(Root([2; 32])),
            Err(WeakSubjectivityError::Conflict {
                epoch: Epoch(3),
                expected: Root([1; 32]),
                actual: Root([2; 32]),
            })
        );
    }
}
