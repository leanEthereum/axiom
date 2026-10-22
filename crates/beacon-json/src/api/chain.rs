//! What a client asks of a node first: the chain's genesis, and how far the node is synced.

use axiom_json::Json;
use axiom_types::{Root, Slot, Version};

use crate::{ApiJson, ApiJsonError, reader::Fields};

/// The chain's genesis, which names the chain and fixes its clock.
///
/// See `getGenesis` in the beacon API.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Genesis {
    /// Unix time of genesis, in seconds.
    pub genesis_time: u64,
    /// Root of the validator registry at genesis.
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

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            genesis_time: fields.required("genesis_time")?,
            genesis_validators_root: fields.required("genesis_validators_root")?,
            genesis_fork_version: fields.required("genesis_fork_version")?,
        })
    }
}

/// How far a node is from the head of the chain.
///
/// See `getSyncingStatus` in the beacon API.
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

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            head_slot: fields.required("head_slot")?,
            sync_distance: fields.required("sync_distance")?,
            is_syncing: fields.required("is_syncing")?,
            is_optimistic: fields.required("is_optimistic")?,
            el_offline: fields.required("el_offline")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_reads_the_beacon_api_example() {
        // The example of getGenesis, member for member.
        let text = r#"{"genesis_time":"1590832934","genesis_validators_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","genesis_fork_version":"0x00000000"}"#;
        let genesis = Genesis::from_json(&Json::parse(text).unwrap()).unwrap();
        assert_eq!(genesis.genesis_time, 1_590_832_934);
        assert_eq!(genesis.genesis_fork_version, Version([0; 4]));
        assert_eq!(genesis.to_json().to_string(), text);
    }

    #[test]
    fn sync_status_round_trips() {
        let status = SyncStatus {
            head_slot: Slot(9),
            sync_distance: 2,
            is_syncing: false,
            is_optimistic: true,
            el_offline: false,
        };
        assert_eq!(SyncStatus::from_json(&status.to_json()), Ok(status));
    }
}
