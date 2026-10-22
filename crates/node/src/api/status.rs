//! The lifecycle statuses the beacon API reports for validators and builders.

use std::{fmt, str::FromStr};

use axiom_types::{Epoch, Gwei, gloas::Builder, phase0::Validator};

use super::reply::ApiError;

/// Where a validator stands in its lifecycle at an epoch.
///
/// The stages follow the activation, exit, and withdrawal epochs of the phase0 registry.
/// See the validator status definition the beacon API links to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ValidatorStatus {
    /// Deposited, but not yet eligible for the activation queue.
    PendingInitialized,
    /// Eligible, waiting in the activation queue.
    PendingQueued,
    /// Active, with no exit scheduled.
    ActiveOngoing,
    /// Active, with a voluntary exit scheduled.
    ActiveExiting,
    /// Active, slashed, and scheduled to exit.
    ActiveSlashed,
    /// Exited without a slashing, not yet withdrawable.
    ExitedUnslashed,
    /// Exited after a slashing, not yet withdrawable.
    ExitedSlashed,
    /// Withdrawable, with a balance left to sweep.
    WithdrawalPossible,
    /// Withdrawable, with nothing left.
    WithdrawalDone,
}

impl ValidatorStatus {
    /// Every status, for matching a filter.
    pub(crate) const ALL: [Self; 9] = [
        Self::PendingInitialized,
        Self::PendingQueued,
        Self::ActiveOngoing,
        Self::ActiveExiting,
        Self::ActiveSlashed,
        Self::ExitedUnslashed,
        Self::ExitedSlashed,
        Self::WithdrawalPossible,
        Self::WithdrawalDone,
    ];

    /// The status of a validator with a balance at an epoch.
    pub(crate) fn of(validator: &Validator, balance: Gwei, epoch: Epoch) -> Self {
        if epoch < validator.activation_epoch {
            if validator.activation_eligibility_epoch == Epoch::FAR_FUTURE {
                Self::PendingInitialized
            } else {
                Self::PendingQueued
            }
        } else if epoch < validator.exit_epoch {
            if validator.exit_epoch == Epoch::FAR_FUTURE {
                Self::ActiveOngoing
            } else if validator.slashed {
                Self::ActiveSlashed
            } else {
                Self::ActiveExiting
            }
        } else if epoch < validator.withdrawable_epoch {
            if validator.slashed {
                Self::ExitedSlashed
            } else {
                Self::ExitedUnslashed
            }
        } else if balance.0 == 0 {
            Self::WithdrawalDone
        } else {
            Self::WithdrawalPossible
        }
    }

    /// The name the beacon API gives the status.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PendingInitialized => "pending_initialized",
            Self::PendingQueued => "pending_queued",
            Self::ActiveOngoing => "active_ongoing",
            Self::ActiveExiting => "active_exiting",
            Self::ActiveSlashed => "active_slashed",
            Self::ExitedUnslashed => "exited_unslashed",
            Self::ExitedSlashed => "exited_slashed",
            Self::WithdrawalPossible => "withdrawal_possible",
            Self::WithdrawalDone => "withdrawal_done",
        }
    }

    /// The broad stage the status belongs to, which a filter may name instead.
    const fn stage(self) -> &'static str {
        match self {
            Self::PendingInitialized | Self::PendingQueued => "pending",
            Self::ActiveOngoing | Self::ActiveExiting | Self::ActiveSlashed => "active",
            Self::ExitedUnslashed | Self::ExitedSlashed => "exited",
            Self::WithdrawalPossible | Self::WithdrawalDone => "withdrawal",
        }
    }
}

impl fmt::Display for ValidatorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The statuses a validator query keeps, from its exact or broad names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct StatusFilter(Vec<ValidatorStatus>);

impl StatusFilter {
    /// Reads status names; an empty list keeps every validator.
    ///
    /// # Errors
    ///
    /// Fails with a bad request on an unknown name.
    pub(crate) fn parse<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Self, ApiError> {
        let mut kept = Vec::new();
        for name in names {
            let matching: Vec<ValidatorStatus> = ValidatorStatus::ALL
                .into_iter()
                .filter(|status| status.as_str() == name || status.stage() == name)
                .collect();
            if matching.is_empty() {
                return Err(ApiError::bad_request(format!("invalid status: {name}")));
            }
            kept.extend(matching);
        }
        Ok(Self(kept))
    }

    /// Whether a status passes the filter.
    pub(crate) fn keeps(&self, status: ValidatorStatus) -> bool {
        self.0.is_empty() || self.0.contains(&status)
    }
}

impl FromStr for StatusFilter {
    type Err = ApiError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text.split(',').filter(|name| !name.is_empty()))
    }
}

/// Where a Gloas builder stands, per the beacon API's builder statuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuilderStatus {
    /// Deposited, but not yet finalized as active.
    Pending,
    /// May bid.
    Active,
    /// Started to exit.
    Exited,
}

impl BuilderStatus {
    /// The status of a builder given the finalized epoch.
    pub(crate) fn of(builder: &Builder, finalized_epoch: Epoch) -> Self {
        if builder.withdrawable_epoch != Epoch::FAR_FUTURE {
            Self::Exited
        } else if builder.is_active(finalized_epoch) {
            Self::Active
        } else {
            Self::Pending
        }
    }

    /// The name the beacon API gives the status.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Exited => "exited",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A validator activated at epoch 10, given exit and withdrawable epochs.
    fn validator(exit: u64, withdrawable: u64, slashed: bool) -> Validator {
        Validator {
            activation_eligibility_epoch: Epoch(5),
            activation_epoch: Epoch(10),
            exit_epoch: Epoch(exit),
            withdrawable_epoch: Epoch(withdrawable),
            slashed,
            ..Validator::default()
        }
    }

    #[test]
    fn each_stage_of_the_lifecycle() {
        let far = u64::MAX;
        let balance = Gwei(32_000_000_000);
        let cases = [
            // Eligible at 5, active from 10: queued at epoch 7.
            (
                validator(far, far, false),
                balance,
                7,
                ValidatorStatus::PendingQueued,
            ),
            (
                validator(far, far, false),
                balance,
                10,
                ValidatorStatus::ActiveOngoing,
            ),
            // Exit at 20, withdrawable at 276.
            (
                validator(20, 276, false),
                balance,
                15,
                ValidatorStatus::ActiveExiting,
            ),
            (
                validator(20, 276, true),
                balance,
                15,
                ValidatorStatus::ActiveSlashed,
            ),
            (
                validator(20, 276, false),
                balance,
                20,
                ValidatorStatus::ExitedUnslashed,
            ),
            (
                validator(20, 276, true),
                balance,
                100,
                ValidatorStatus::ExitedSlashed,
            ),
            (
                validator(20, 276, false),
                balance,
                276,
                ValidatorStatus::WithdrawalPossible,
            ),
            (
                validator(20, 276, false),
                Gwei(0),
                276,
                ValidatorStatus::WithdrawalDone,
            ),
        ];
        for (validator, balance, epoch, expected) in cases {
            assert_eq!(
                ValidatorStatus::of(&validator, balance, Epoch(epoch)),
                expected
            );
        }

        // Never made eligible: still initializing.
        let fresh = Validator {
            activation_eligibility_epoch: Epoch::FAR_FUTURE,
            activation_epoch: Epoch::FAR_FUTURE,
            ..Validator::default()
        };
        assert_eq!(
            ValidatorStatus::of(&fresh, balance, Epoch(0)),
            ValidatorStatus::PendingInitialized
        );
    }

    #[test]
    fn filters_take_exact_and_broad_names() {
        // "active" covers three statuses, and an exact name adds one more.
        let filter: StatusFilter = "active,withdrawal_done".parse().unwrap();
        assert!(filter.keeps(ValidatorStatus::ActiveSlashed));
        assert!(filter.keeps(ValidatorStatus::WithdrawalDone));
        assert!(!filter.keeps(ValidatorStatus::WithdrawalPossible));

        // No filter keeps everything; an unknown name is refused.
        assert!(StatusFilter::default().keeps(ValidatorStatus::PendingQueued));
        assert_eq!(
            "retired".parse::<StatusFilter>(),
            Err(ApiError::bad_request("invalid status: retired"))
        );
    }

    #[test]
    fn builders_exit_before_anything_else() {
        let builder = |deposit, withdrawable| Builder {
            deposit_epoch: Epoch(deposit),
            withdrawable_epoch: Epoch(withdrawable),
            ..Builder::default()
        };
        // Finalized epoch 10: a deposit at 9 is active, one at 10 still pending.
        assert_eq!(
            BuilderStatus::of(&builder(9, u64::MAX), Epoch(10)),
            BuilderStatus::Active
        );
        assert_eq!(
            BuilderStatus::of(&builder(10, u64::MAX), Epoch(10)),
            BuilderStatus::Pending
        );
        assert_eq!(
            BuilderStatus::of(&builder(9, 50), Epoch(10)),
            BuilderStatus::Exited
        );
    }
}
