//! Payload attributes, versions V1 to V4: what a proposer asks the engine to build.
//!
//! Each version appends members to the one before it.
//!
//! ```text
//!     JSON member             encoding           V1  V2  V3  V4
//!     timestamp               QUANTITY 64        x   x   x   x
//!     prevRandao              DATA 32            x   x   x   x
//!     suggestedFeeRecipient   DATA 20            x   x   x   x
//!     withdrawals             WithdrawalV1s          x   x   x
//!     parentBeaconBlockRoot   DATA 32                    x   x
//!     slotNumber              QUANTITY 64                    x
//!     targetGasLimit          QUANTITY 64                    x
//! ```
//!
//! The versions are defined in the Paris, Shanghai, Cancun, and Amsterdam files of `src/engine/`.
//! The consensus layer fills them from its state, as `prepare_execution_payload` does.

use axiom_json::Json;
use axiom_types::{Bytes32, ExecutionAddress, Preset, Root, Slot, capella, gloas};

use super::{Fields, JsonCodec};
use crate::{ForkchoiceVersion, WireError};

/// Build attributes of Bellatrix.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadAttributesV1 {
    /// Timestamp of the slot the payload is for.
    pub timestamp: u64,

    /// Randao mix of the current epoch.
    pub prev_randao: Bytes32,

    /// Address to receive the fees, a suggestion the builder may override.
    pub suggested_fee_recipient: ExecutionAddress,
}

impl JsonCodec for PayloadAttributesV1 {
    fn to_json(&self) -> Json {
        Json::from([
            ("timestamp", self.timestamp.to_json()),
            ("prevRandao", self.prev_randao.to_json()),
            (
                "suggestedFeeRecipient",
                self.suggested_fee_recipient.to_json(),
            ),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            timestamp: fields.required("timestamp")?,
            prev_randao: fields.required("prevRandao")?,
            suggested_fee_recipient: fields.required("suggestedFeeRecipient")?,
        })
    }
}

/// Build attributes of Capella, which add the withdrawals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadAttributesV2<P: Preset> {
    /// Timestamp of the slot the payload is for.
    pub timestamp: u64,

    /// Randao mix of the current epoch.
    pub prev_randao: Bytes32,

    /// Address to receive the fees, a suggestion the builder may override.
    pub suggested_fee_recipient: ExecutionAddress,

    /// Withdrawals the payload must contain, from the expected withdrawals sweep.
    pub withdrawals: capella::Withdrawals<P>,
}

impl<P: Preset> JsonCodec for PayloadAttributesV2<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("timestamp", self.timestamp.to_json()),
            ("prevRandao", self.prev_randao.to_json()),
            (
                "suggestedFeeRecipient",
                self.suggested_fee_recipient.to_json(),
            ),
            ("withdrawals", self.withdrawals.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            timestamp: fields.required("timestamp")?,
            prev_randao: fields.required("prevRandao")?,
            suggested_fee_recipient: fields.required("suggestedFeeRecipient")?,
            withdrawals: fields.required("withdrawals")?,
        })
    }
}

/// Build attributes of Deneb, Electra, and Fulu, which add the parent beacon block root.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadAttributesV3<P: Preset> {
    /// Timestamp of the slot the payload is for.
    pub timestamp: u64,

    /// Randao mix of the current epoch.
    pub prev_randao: Bytes32,

    /// Address to receive the fees, a suggestion the builder may override.
    pub suggested_fee_recipient: ExecutionAddress,

    /// Withdrawals the payload must contain, from the expected withdrawals sweep.
    pub withdrawals: capella::Withdrawals<P>,

    /// Root of the beacon block the new block will build on, see EIP-4788.
    pub parent_beacon_block_root: Root,
}

impl<P: Preset> JsonCodec for PayloadAttributesV3<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("timestamp", self.timestamp.to_json()),
            ("prevRandao", self.prev_randao.to_json()),
            (
                "suggestedFeeRecipient",
                self.suggested_fee_recipient.to_json(),
            ),
            ("withdrawals", self.withdrawals.to_json()),
            (
                "parentBeaconBlockRoot",
                self.parent_beacon_block_root.to_json(),
            ),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            timestamp: fields.required("timestamp")?,
            prev_randao: fields.required("prevRandao")?,
            suggested_fee_recipient: fields.required("suggestedFeeRecipient")?,
            withdrawals: fields.required("withdrawals")?,
            parent_beacon_block_root: fields.required("parentBeaconBlockRoot")?,
        })
    }
}

/// Build attributes of Gloas, which add the slot and the gas limit to aim for.
///
/// Gloas withdrawal lists are progressive, so they have no limit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadAttributesV4 {
    /// Timestamp of the slot the payload is for.
    pub timestamp: u64,

    /// Randao mix of the current epoch.
    pub prev_randao: Bytes32,

    /// Address to receive the fees, a suggestion the builder may override.
    pub suggested_fee_recipient: ExecutionAddress,

    /// Withdrawals the payload must contain, from the expected withdrawals sweep.
    pub withdrawals: gloas::Withdrawals,

    /// Root of the beacon block the new block will build on, see EIP-4788.
    pub parent_beacon_block_root: Root,

    /// Slot the payload is for, see EIP-7843.
    pub slot_number: Slot,

    /// Gas limit the engine must aim the payload's limit at.
    pub target_gas_limit: u64,
}

impl JsonCodec for PayloadAttributesV4 {
    fn to_json(&self) -> Json {
        Json::from([
            ("timestamp", self.timestamp.to_json()),
            ("prevRandao", self.prev_randao.to_json()),
            (
                "suggestedFeeRecipient",
                self.suggested_fee_recipient.to_json(),
            ),
            ("withdrawals", self.withdrawals.to_json()),
            (
                "parentBeaconBlockRoot",
                self.parent_beacon_block_root.to_json(),
            ),
            ("slotNumber", self.slot_number.to_json()),
            ("targetGasLimit", self.target_gas_limit.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            timestamp: fields.required("timestamp")?,
            prev_randao: fields.required("prevRandao")?,
            suggested_fee_recipient: fields.required("suggestedFeeRecipient")?,
            withdrawals: fields.required("withdrawals")?,
            parent_beacon_block_root: fields.required("parentBeaconBlockRoot")?,
            slot_number: fields.required("slotNumber")?,
            target_gas_limit: fields.required("targetGasLimit")?,
        })
    }
}

/// Build attributes of whichever version the fork calls.
///
/// The version fixes the fork choice method, so the client checks it against the fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadAttributes<P: Preset> {
    /// Bellatrix attributes.
    V1(PayloadAttributesV1),
    /// Capella attributes.
    V2(PayloadAttributesV2<P>),
    /// Deneb, Electra, and Fulu attributes.
    V3(PayloadAttributesV3<P>),
    /// Gloas attributes.
    V4(PayloadAttributesV4),
}

impl<P: Preset> PayloadAttributes<P> {
    /// The fork choice method these attributes belong to.
    #[must_use]
    pub const fn version(&self) -> ForkchoiceVersion {
        match self {
            Self::V1(_) => ForkchoiceVersion::V1,
            Self::V2(_) => ForkchoiceVersion::V2,
            Self::V3(_) => ForkchoiceVersion::V3,
            Self::V4(_) => ForkchoiceVersion::V4,
        }
    }

    /// The JSON form of the version held.
    pub(crate) fn to_json(&self) -> Json {
        match self {
            Self::V1(attributes) => attributes.to_json(),
            Self::V2(attributes) => attributes.to_json(),
            Self::V3(attributes) => attributes.to_json(),
            Self::V4(attributes) => attributes.to_json(),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::{List, ProgressiveList};
    use axiom_types::Minimal;
    use proptest::prelude::*;

    use super::*;
    use crate::wire::payload::tests::withdrawal;

    proptest! {
        #[test]
        fn attributes_round_trip(
            withdrawals in proptest::collection::vec(withdrawal(), 0..=4),
            numbers in any::<[u64; 3]>(),
            hashes in any::<[[u8; 32]; 3]>(),
        ) {
            let [timestamp, slot, gas] = numbers;
            let v1 = PayloadAttributesV1 {
                timestamp,
                prev_randao: Bytes32(hashes[0]),
                suggested_fee_recipient: ExecutionAddress([hashes[1][0]; 20]),
            };
            let v2 = PayloadAttributesV2::<Minimal> {
                timestamp,
                prev_randao: v1.prev_randao,
                suggested_fee_recipient: v1.suggested_fee_recipient,
                withdrawals: List::try_from(withdrawals.clone()).unwrap(),
            };
            let v3 = PayloadAttributesV3::<Minimal> {
                timestamp,
                prev_randao: v1.prev_randao,
                suggested_fee_recipient: v1.suggested_fee_recipient,
                withdrawals: v2.withdrawals.clone(),
                parent_beacon_block_root: Root(hashes[2]),
            };
            let v4 = PayloadAttributesV4 {
                timestamp,
                prev_randao: v1.prev_randao,
                suggested_fee_recipient: v1.suggested_fee_recipient,
                withdrawals: ProgressiveList::from(withdrawals),
                parent_beacon_block_root: v3.parent_beacon_block_root,
                slot_number: Slot(slot),
                target_gas_limit: gas,
            };
            prop_assert_eq!(PayloadAttributesV1::from_json(&v1.to_json()), Ok(v1));
            prop_assert_eq!(PayloadAttributesV2::from_json(&v2.to_json()), Ok(v2));
            prop_assert_eq!(PayloadAttributesV3::from_json(&v3.to_json()), Ok(v3));
            prop_assert_eq!(PayloadAttributesV4::from_json(&v4.to_json()), Ok(v4));
        }
    }
}
