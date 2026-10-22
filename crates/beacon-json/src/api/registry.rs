//! Views of the validator registry: a validator with its status, and its liveness.

use axiom_json::Json;
use axiom_types::{Gwei, ValidatorIndex, phase0::Validator};

use crate::{ApiJson, ApiJsonError, ApiJsonErrorKind, reader::Fields};

/// A validator's lifecycle stage, as the beacon API names it.
///
/// See the validator status rules linked from the beacon API's state validators route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValidatorStatus {
    /// Deposited, not yet eligible.
    PendingInitialized,
    /// Eligible, waiting in the activation queue.
    PendingQueued,
    /// Active, with no exit scheduled.
    ActiveOngoing,
    /// Active, with an exit scheduled.
    ActiveExiting,
    /// Active, slashed, with the exit forced.
    ActiveSlashed,
    /// Exited without slashing.
    ExitedUnslashed,
    /// Exited after slashing.
    ExitedSlashed,
    /// The balance may now be withdrawn.
    WithdrawalPossible,
    /// The balance has been withdrawn.
    WithdrawalDone,
}

impl ValidatorStatus {
    /// Every status, in lifecycle order.
    pub const ALL: [Self; 9] = [
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

    /// The API's name of the status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
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

    /// Whether the validator is in the active set and has duties.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::ActiveOngoing | Self::ActiveExiting | Self::ActiveSlashed
        )
    }
}

impl ApiJson for ValidatorStatus {
    fn to_json(&self) -> Json {
        Json::from(self.as_str())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let name = value
            .as_str()
            .ok_or_else(|| ApiJsonError::wrong_type("a status name", value))?;
        Self::ALL
            .into_iter()
            .find(|status| status.as_str() == name)
            .ok_or_else(|| ApiJsonError::new(ApiJsonErrorKind::UnknownName(name.to_owned())))
    }
}

/// A validator of a state, with its index, balance, and status.
///
/// See `ValidatorResponse` in the beacon API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorResponse {
    /// Position in the registry.
    pub index: ValidatorIndex,
    /// Current balance.
    pub balance: Gwei,
    /// Lifecycle stage.
    pub status: ValidatorStatus,
    /// The registry record.
    pub validator: Validator,
}

impl ApiJson for ValidatorResponse {
    fn to_json(&self) -> Json {
        Json::from([
            ("index", self.index.to_json()),
            ("balance", self.balance.to_json()),
            ("status", self.status.to_json()),
            ("validator", self.validator.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            index: fields.required("index")?,
            balance: fields.required("balance")?,
            status: fields.required("status")?,
            validator: fields.required("validator")?,
        })
    }
}

/// Whether a validator was seen on the network during an epoch.
///
/// See `getLiveness` in the beacon API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Liveness {
    /// The validator.
    pub index: ValidatorIndex,
    /// Whether a message of it was seen.
    pub is_live: bool,
}

impl ApiJson for Liveness {
    fn to_json(&self) -> Json {
        Json::from([
            ("index", self.index.to_json()),
            ("is_live", self.is_live.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            index: fields.required("index")?,
            is_live: fields.required("is_live")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{BlsPubkey, Epoch};

    use super::*;

    #[test]
    fn every_status_reads_back_and_an_unknown_one_is_named() {
        for status in ValidatorStatus::ALL {
            assert_eq!(ValidatorStatus::from_json(&status.to_json()), Ok(status));
        }
        assert_eq!(
            ValidatorStatus::from_json(&Json::from("active_dancing")),
            Err(ApiJsonError::new(ApiJsonErrorKind::UnknownName(
                "active_dancing".to_owned()
            )))
        );
    }

    #[test]
    fn a_validator_response_round_trips() {
        let response = ValidatorResponse {
            index: ValidatorIndex(3),
            balance: Gwei(32_000_000_000),
            status: ValidatorStatus::ActiveOngoing,
            validator: Validator {
                pubkey: BlsPubkey([1; 48]),
                activation_epoch: Epoch(0),
                exit_epoch: Epoch::FAR_FUTURE,
                ..Validator::default()
            },
        };
        assert_eq!(
            ValidatorResponse::from_json(&response.to_json()),
            Ok(response)
        );
        let liveness = Liveness {
            index: ValidatorIndex(3),
            is_live: true,
        };
        assert_eq!(Liveness::from_json(&liveness.to_json()), Ok(liveness));
    }
}
