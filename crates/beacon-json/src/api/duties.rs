//! Validator duties: proposals, committee seats, sync committee seats, and timeliness seats.

use axiom_json::{Json, Object};
use axiom_types::{BlsPubkey, CommitteeIndex, Root, Slot, ValidatorIndex};

use crate::{ApiJson, ApiJsonError, reader::Fields};

/// The duties of an epoch, with the block root their shuffling depends on.
///
/// When the head moves to a branch with another dependent root, the duties must be fetched again.
/// Sync committee duties follow the period instead, and carry no dependent root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Duties<T> {
    /// The root the duties depend on, absent for sync committee duties.
    pub dependent_root: Option<Root>,
    /// Whether the node computed them on an unvalidated payload.
    pub execution_optimistic: bool,
    /// The duties.
    pub data: Vec<T>,
}

impl<T: ApiJson> ApiJson for Duties<T> {
    fn to_json(&self) -> Json {
        let mut object = Object::new();
        if let Some(root) = self.dependent_root {
            object.insert("dependent_root", root.to_json());
        }
        object.insert("execution_optimistic", self.execution_optimistic.to_json());
        object.insert("data", self.data.to_json());
        Json::Object(object)
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            dependent_root: fields.optional("dependent_root")?,
            execution_optimistic: fields.required("execution_optimistic")?,
            data: fields.required("data")?,
        })
    }
}

/// A block a validator must propose.
///
/// See `ProposerDuty` in the beacon API.
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

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            pubkey: fields.required("pubkey")?,
            validator_index: fields.required("validator_index")?,
            slot: fields.required("slot")?,
        })
    }
}

/// A committee seat a validator must vote from.
///
/// See `AttesterDuty` in the beacon API.
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

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            pubkey: fields.required("pubkey")?,
            validator_index: fields.required("validator_index")?,
            committee_index: fields.required("committee_index")?,
            committee_length: fields.required("committee_length")?,
            committees_at_slot: fields.required("committees_at_slot")?,
            validator_committee_index: fields.required("validator_committee_index")?,
            slot: fields.required("slot")?,
        })
    }
}

/// A validator's seats in the sync committee of a period.
///
/// See `SyncDuty` in the beacon API.
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

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            pubkey: fields.required("pubkey")?,
            validator_index: fields.required("validator_index")?,
            validator_sync_committee_indices: fields
                .required("validator_sync_committee_indices")?,
        })
    }
}

/// A payload timeliness committee seat at a slot.
///
/// See `PtcDuty` in the beacon API and `get_ptc_assignment` in the Gloas validator spec.
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

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            pubkey: fields.required("pubkey")?,
            validator_index: fields.required("validator_index")?,
            slot: fields.required("slot")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attester_duties_read_the_beacon_api_example() {
        // The example of getAttesterDuties, member for member.
        let text = r#"{"dependent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","execution_optimistic":false,"data":[{"pubkey":"0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a","validator_index":"1","committee_index":"1","committee_length":"1","committees_at_slot":"1","validator_committee_index":"1","slot":"1"}]}"#;
        let duties = Duties::<AttesterDuty>::from_json(&Json::parse(text).unwrap()).unwrap();
        assert_eq!(duties.data[0].validator_index, ValidatorIndex(1));
        assert_eq!(duties.data[0].slot, Slot(1));
        assert_eq!(duties.to_json().to_string(), text);
    }

    #[test]
    fn sync_duties_carry_no_dependent_root() {
        // A sync duty with two seats, and no root in the envelope.
        let duties = Duties {
            dependent_root: None,
            execution_optimistic: true,
            data: vec![SyncDuty {
                pubkey: BlsPubkey([2; 48]),
                validator_index: ValidatorIndex(4),
                validator_sync_committee_indices: vec![0, 7],
            }],
        };
        let json = duties.to_json();
        assert_eq!(json.get("dependent_root"), None);
        assert_eq!(Duties::from_json(&json), Ok(duties));
        let ptc = PtcDuty {
            pubkey: BlsPubkey([3; 48]),
            validator_index: ValidatorIndex(5),
            slot: Slot(9),
        };
        assert_eq!(PtcDuty::from_json(&ptc.to_json()), Ok(ptc));
        let proposer = ProposerDuty {
            pubkey: BlsPubkey([4; 48]),
            validator_index: ValidatorIndex(6),
            slot: Slot(10),
        };
        assert_eq!(ProposerDuty::from_json(&proposer.to_json()), Ok(proposer));
    }
}
