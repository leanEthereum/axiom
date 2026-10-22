//! The beacon API's own messages: duties, statuses, subscriptions, and preparations.
//!
//! See the `ethereum/beacon-APIs` repository, types directory.

use axiom_json::Json;
use axiom_types::{
    BlsPubkey, CommitteeIndex, Epoch, ExecutionAddress, Gwei, Root, Slot, ValidatorIndex, Version,
};

use crate::json::{ApiJson, Fields, JsonError};

/// What a validator needs to know about the chain before it signs anything.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Genesis {
    /// Unix time of genesis, in seconds.
    pub genesis_time: u64,
    /// Root of the validator registry at genesis, which names the chain.
    pub genesis_validators_root: Root,
    /// Fork version at genesis.
    pub genesis_fork_version: Version,
}

impl ApiJson for Genesis {
    fn to_json(&self) -> Json {
        Json::from([
            ("genesis_time", self.genesis_time.to_json()),
            (
                "genesis_validators_root",
                self.genesis_validators_root.to_json(),
            ),
            ("genesis_fork_version", self.genesis_fork_version.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            genesis_time: fields.get("genesis_time")?,
            genesis_validators_root: fields.get("genesis_validators_root")?,
            genesis_fork_version: fields.get("genesis_fork_version")?,
        })
    }
}

/// How far a node is from the head of the chain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncStatus {
    /// The node's head slot.
    pub head_slot: Slot,
    /// Slots between the head and the wall clock.
    pub sync_distance: u64,
    /// Whether the node is still syncing.
    pub is_syncing: bool,
    /// Whether the head rests on a payload the engine has not validated.
    pub is_optimistic: bool,
    /// Whether the execution engine is unreachable.
    pub el_offline: bool,
}

impl ApiJson for SyncStatus {
    fn to_json(&self) -> Json {
        Json::from([
            ("head_slot", self.head_slot.to_json()),
            ("sync_distance", self.sync_distance.to_json()),
            ("is_syncing", self.is_syncing.to_json()),
            ("is_optimistic", self.is_optimistic.to_json()),
            ("el_offline", self.el_offline.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            head_slot: fields.get("head_slot")?,
            sync_distance: fields.get("sync_distance")?,
            is_syncing: fields.get("is_syncing")?,
            // Older nodes leave out the newer flags.
            is_optimistic: fields.optional("is_optimistic")?.unwrap_or(false),
            el_offline: fields.optional("el_offline")?.unwrap_or(false),
        })
    }
}

/// A validator's lifecycle stage, as the beacon API names it.
///
/// See the validator status specification linked from the beacon API.
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

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let name = String::from_json(json)?;
        Self::ALL
            .into_iter()
            .find(|status| status.as_str() == name)
            .ok_or(JsonError::Unknown(name))
    }
}

/// A validator as a beacon node's state records it, reduced to what a client needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatorSummary {
    /// Position in the registry.
    pub index: ValidatorIndex,
    /// The signing key.
    pub pubkey: BlsPubkey,
    /// Lifecycle stage.
    pub status: ValidatorStatus,
    /// Current balance.
    pub balance: Gwei,
    /// Epoch it became, or becomes, active.
    pub activation_epoch: Epoch,
    /// Epoch it exits, or the far future.
    pub exit_epoch: Epoch,
}

impl ApiJson for ValidatorSummary {
    fn to_json(&self) -> Json {
        Json::from([
            ("index", self.index.to_json()),
            ("balance", self.balance.to_json()),
            ("status", self.status.to_json()),
            (
                "validator",
                Json::from([
                    ("pubkey", self.pubkey.to_json()),
                    ("activation_epoch", self.activation_epoch.to_json()),
                    ("exit_epoch", self.exit_epoch.to_json()),
                ]),
            ),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        let validator = Fields::of(fields.raw("validator")?)?;
        Ok(Self {
            index: fields.get("index")?,
            pubkey: validator.get("pubkey")?,
            status: fields.get("status")?,
            balance: fields.get("balance")?,
            activation_epoch: validator.get("activation_epoch")?,
            exit_epoch: validator.get("exit_epoch")?,
        })
    }
}

/// Duties of an epoch, with the block root they depend on.
///
/// The dependent root names the block whose state fixed the shuffling.
/// When the head moves to a branch with another dependent root, the duties must be fetched again.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Duties<T> {
    /// The root the duties depend on.
    pub dependent_root: Root,
    /// Whether the node computed them from an unvalidated payload.
    pub execution_optimistic: bool,
    /// The duties.
    pub data: Vec<T>,
}

impl<T: ApiJson> ApiJson for Duties<T> {
    fn to_json(&self) -> Json {
        Json::from([
            ("dependent_root", self.dependent_root.to_json()),
            ("execution_optimistic", self.execution_optimistic.to_json()),
            ("data", self.data.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            // Sync duties carry no dependent root: they follow the sync committee period.
            dependent_root: fields.optional("dependent_root")?.unwrap_or(Root::ZERO),
            execution_optimistic: fields.optional("execution_optimistic")?.unwrap_or(false),
            data: fields.get("data")?,
        })
    }
}

/// A block a validator must propose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposerDuty {
    /// The proposer's key.
    pub pubkey: BlsPubkey,
    /// The proposer.
    pub validator_index: ValidatorIndex,
    /// The slot of the block.
    pub slot: Slot,
}

impl ApiJson for ProposerDuty {
    fn to_json(&self) -> Json {
        Json::from([
            ("pubkey", self.pubkey.to_json()),
            ("validator_index", self.validator_index.to_json()),
            ("slot", self.slot.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            pubkey: fields.get("pubkey")?,
            validator_index: fields.get("validator_index")?,
            slot: fields.get("slot")?,
        })
    }
}

/// A committee seat a validator must vote from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttesterDuty {
    /// The attester's key.
    pub pubkey: BlsPubkey,
    /// The attester.
    pub validator_index: ValidatorIndex,
    /// The committee.
    pub committee_index: CommitteeIndex,
    /// Members of the committee.
    pub committee_length: u64,
    /// Committees at the slot.
    pub committees_at_slot: u64,
    /// The attester's position in the committee.
    pub validator_committee_index: u64,
    /// The slot to vote at.
    pub slot: Slot,
}

impl ApiJson for AttesterDuty {
    fn to_json(&self) -> Json {
        Json::from([
            ("pubkey", self.pubkey.to_json()),
            ("validator_index", self.validator_index.to_json()),
            ("committee_index", self.committee_index.to_json()),
            ("committee_length", self.committee_length.to_json()),
            ("committees_at_slot", self.committees_at_slot.to_json()),
            (
                "validator_committee_index",
                self.validator_committee_index.to_json(),
            ),
            ("slot", self.slot.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            pubkey: fields.get("pubkey")?,
            validator_index: fields.get("validator_index")?,
            committee_index: fields.get("committee_index")?,
            committee_length: fields.get("committee_length")?,
            committees_at_slot: fields.get("committees_at_slot")?,
            validator_committee_index: fields.get("validator_committee_index")?,
            slot: fields.get("slot")?,
        })
    }
}

/// A validator's seats in the sync committee of a period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncDuty {
    /// The member's key.
    pub pubkey: BlsPubkey,
    /// The member.
    pub validator_index: ValidatorIndex,
    /// Its seats in the committee, possibly several.
    pub validator_sync_committee_indices: Vec<u64>,
}

impl ApiJson for SyncDuty {
    fn to_json(&self) -> Json {
        Json::from([
            ("pubkey", self.pubkey.to_json()),
            ("validator_index", self.validator_index.to_json()),
            (
                "validator_sync_committee_indices",
                self.validator_sync_committee_indices.to_json(),
            ),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            pubkey: fields.get("pubkey")?,
            validator_index: fields.get("validator_index")?,
            validator_sync_committee_indices: fields.get("validator_sync_committee_indices")?,
        })
    }
}

/// A payload timeliness committee seat at a slot.
///
/// See `get_ptc_assignment` in the Gloas validator spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtcDuty {
    /// The member's key.
    pub pubkey: BlsPubkey,
    /// The member.
    pub validator_index: ValidatorIndex,
    /// The slot to vote on.
    pub slot: Slot,
}

impl ApiJson for PtcDuty {
    fn to_json(&self) -> Json {
        Json::from([
            ("pubkey", self.pubkey.to_json()),
            ("validator_index", self.validator_index.to_json()),
            ("slot", self.slot.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            pubkey: fields.get("pubkey")?,
            validator_index: fields.get("validator_index")?,
            slot: fields.get("slot")?,
        })
    }
}

/// A request that the node follow a committee's subnet for a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconCommitteeSubscription {
    /// The attester.
    pub validator_index: ValidatorIndex,
    /// Its committee.
    pub committee_index: CommitteeIndex,
    /// Committees at the slot, which fixes the subnet.
    pub committees_at_slot: u64,
    /// The slot.
    pub slot: Slot,
    /// Whether the attester aggregates, so the node must collect the subnet's votes.
    pub is_aggregator: bool,
}

impl ApiJson for BeaconCommitteeSubscription {
    fn to_json(&self) -> Json {
        Json::from([
            ("validator_index", self.validator_index.to_json()),
            ("committee_index", self.committee_index.to_json()),
            ("committees_at_slot", self.committees_at_slot.to_json()),
            ("slot", self.slot.to_json()),
            ("is_aggregator", self.is_aggregator.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            validator_index: fields.get("validator_index")?,
            committee_index: fields.get("committee_index")?,
            committees_at_slot: fields.get("committees_at_slot")?,
            slot: fields.get("slot")?,
            is_aggregator: fields.get("is_aggregator")?,
        })
    }
}

/// A request that the node follow a sync member's subnets until an epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncCommitteeSubscription {
    /// The member.
    pub validator_index: ValidatorIndex,
    /// Its seats.
    pub sync_committee_indices: Vec<u64>,
    /// The first epoch the subscription no longer covers.
    pub until_epoch: Epoch,
}

impl ApiJson for SyncCommitteeSubscription {
    fn to_json(&self) -> Json {
        Json::from([
            ("validator_index", self.validator_index.to_json()),
            (
                "sync_committee_indices",
                self.sync_committee_indices.to_json(),
            ),
            ("until_epoch", self.until_epoch.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            validator_index: fields.get("validator_index")?,
            sync_committee_indices: fields.get("sync_committee_indices")?,
            until_epoch: fields.get("until_epoch")?,
        })
    }
}

/// Where a proposer's execution fees go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposerPreparation {
    /// The proposer.
    pub validator_index: ValidatorIndex,
    /// The fee recipient.
    pub fee_recipient: ExecutionAddress,
}

impl ApiJson for ProposerPreparation {
    fn to_json(&self) -> Json {
        Json::from([
            ("validator_index", self.validator_index.to_json()),
            ("fee_recipient", self.fee_recipient.to_json()),
        ])
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            validator_index: fields.get("validator_index")?,
            fee_recipient: fields.get("fee_recipient")?,
        })
    }
}

/// Whether a validator was seen on the network during an epoch.
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

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let fields = Fields::of(json)?;
        Ok(Self {
            index: fields.get("index")?,
            is_live: fields.get("is_live")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_attester_duty_reads_the_beacon_api_example() {
        // The example of the beacon API, field for field.
        let text = r#"{"pubkey":"0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a","validator_index":"1","committee_index":"1","committee_length":"1","committees_at_slot":"1","validator_committee_index":"1","slot":"1"}"#;
        let duty = AttesterDuty::from_json(&Json::parse(text).unwrap()).unwrap();
        assert_eq!(duty.validator_index, ValidatorIndex(1));
        assert_eq!(duty.slot, Slot(1));
        assert_eq!(duty.to_json().to_string(), text);
    }

    #[test]
    fn an_unknown_status_is_named() {
        assert_eq!(
            ValidatorStatus::from_json(&Json::from("active_dancing")),
            Err(JsonError::Unknown("active_dancing".to_owned()))
        );
        assert_eq!(
            ValidatorStatus::from_json(&Json::from("active_exiting")),
            Ok(ValidatorStatus::ActiveExiting)
        );
    }
}
