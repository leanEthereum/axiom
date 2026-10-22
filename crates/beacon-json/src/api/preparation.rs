//! What a client tells a node ahead of its duties: subnets, fee recipients, and selections.

use axiom_json::Json;
use axiom_types::{BlsSignature, CommitteeIndex, Epoch, ExecutionAddress, Slot, ValidatorIndex};

use crate::{ApiJson, ApiJsonError, reader::Fields};

/// A request that a node follow a committee's subnet for a slot.
///
/// See `prepareBeaconCommitteeSubnet` in the beacon API.
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

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            validator_index: fields.required("validator_index")?,
            committee_index: fields.required("committee_index")?,
            committees_at_slot: fields.required("committees_at_slot")?,
            slot: fields.required("slot")?,
            is_aggregator: fields.required("is_aggregator")?,
        })
    }
}

/// A request that a node follow a sync committee member's subnets until an epoch.
///
/// See `prepareSyncCommitteeSubnets` in the beacon API.
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

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            validator_index: fields.required("validator_index")?,
            sync_committee_indices: fields.required("sync_committee_indices")?,
            until_epoch: fields.required("until_epoch")?,
        })
    }
}

/// Where a proposer's execution fees go.
///
/// See `prepareBeaconProposer` in the beacon API.
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

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            validator_index: fields.required("validator_index")?,
            fee_recipient: fields.required("fee_recipient")?,
        })
    }
}

/// A committee seat's slot signature, which a distributed validator combines.
///
/// See `submitBeaconCommitteeSelections` in the beacon API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconCommitteeSelection {
    /// The attester.
    pub validator_index: ValidatorIndex,
    /// The slot.
    pub slot: Slot,
    /// The slot signature, partial or combined.
    pub selection_proof: BlsSignature,
}

impl ApiJson for BeaconCommitteeSelection {
    fn to_json(&self) -> Json {
        Json::from([
            ("validator_index", self.validator_index.to_json()),
            ("slot", self.slot.to_json()),
            ("selection_proof", self.selection_proof.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            validator_index: fields.required("validator_index")?,
            slot: fields.required("slot")?,
            selection_proof: fields.required("selection_proof")?,
        })
    }
}

/// A sync subcommittee seat's selection signature, which a distributed validator combines.
///
/// See `submitSyncCommitteeSelections` in the beacon API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncCommitteeSelection {
    /// The member.
    pub validator_index: ValidatorIndex,
    /// The slot.
    pub slot: Slot,
    /// The subcommittee.
    pub subcommittee_index: u64,
    /// The selection signature, partial or combined.
    pub selection_proof: BlsSignature,
}

impl ApiJson for SyncCommitteeSelection {
    fn to_json(&self) -> Json {
        Json::from([
            ("validator_index", self.validator_index.to_json()),
            ("slot", self.slot.to_json()),
            ("subcommittee_index", self.subcommittee_index.to_json()),
            ("selection_proof", self.selection_proof.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            validator_index: fields.required("validator_index")?,
            slot: fields.required("slot")?,
            subcommittee_index: fields.required("subcommittee_index")?,
            selection_proof: fields.required("selection_proof")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_preparation_round_trips() {
        let subscription = BeaconCommitteeSubscription {
            validator_index: ValidatorIndex(1),
            committee_index: CommitteeIndex(2),
            committees_at_slot: 4,
            slot: Slot(9),
            is_aggregator: true,
        };
        assert_eq!(
            BeaconCommitteeSubscription::from_json(&subscription.to_json()),
            Ok(subscription)
        );
        let sync = SyncCommitteeSubscription {
            validator_index: ValidatorIndex(1),
            sync_committee_indices: vec![3, 300],
            until_epoch: Epoch(512),
        };
        assert_eq!(
            SyncCommitteeSubscription::from_json(&sync.to_json()),
            Ok(sync)
        );
        let preparation = ProposerPreparation {
            validator_index: ValidatorIndex(1),
            fee_recipient: ExecutionAddress([5; 20]),
        };
        assert_eq!(
            ProposerPreparation::from_json(&preparation.to_json()),
            Ok(preparation)
        );
        let selection = BeaconCommitteeSelection {
            validator_index: ValidatorIndex(1),
            slot: Slot(9),
            selection_proof: BlsSignature([6; 96]),
        };
        assert_eq!(
            BeaconCommitteeSelection::from_json(&selection.to_json()),
            Ok(selection)
        );
        let sync_selection = SyncCommitteeSelection {
            validator_index: ValidatorIndex(1),
            slot: Slot(9),
            subcommittee_index: 3,
            selection_proof: BlsSignature([7; 96]),
        };
        assert_eq!(
            SyncCommitteeSelection::from_json(&sync_selection.to_json()),
            Ok(sync_selection)
        );
    }
}
