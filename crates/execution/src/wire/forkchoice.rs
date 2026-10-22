//! Fork choice updates: the state, the build attributes, and the reply.
//!
//! ForkchoiceStateV1 is in `src/engine/paris.md`, PayloadAttributesV3 in `cancun.md`.
//!
//! ```text
//!     ForkchoiceStateV1     headBlockHash, safeBlockHash, finalizedBlockHash   DATA 32 each
//!     PayloadAttributesV3   timestamp              QUANTITY 64
//!                           prevRandao             DATA 32
//!                           suggestedFeeRecipient  DATA 20
//!                           withdrawals            array of WithdrawalV1
//!                           parentBeaconBlockRoot  DATA 32
//!     reply                 payloadStatus          PayloadStatusV1
//!                           payloadId              DATA 8 or null
//! ```

use std::fmt;

use axiom_json::{Data, Json};
use axiom_types::{Bytes32, ExecutionAddress, Hash32, Preset, Root, Withdrawals};

use super::{Fields, JsonCodec, PayloadStatus, nullable, object, primitives::read_fixed};
use crate::WireError;

/// The execution blocks the consensus layer considers head, safe, and finalized.
///
/// Zero hashes are allowed for safe and finalized before the merge block finalizes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ForkchoiceState {
    /// Block hash of the canonical head.
    pub head_block_hash: Hash32,

    /// Block hash of the safe block, an ancestor of the head.
    pub safe_block_hash: Hash32,

    /// Block hash of the latest finalized block.
    pub finalized_block_hash: Hash32,
}

impl JsonCodec for ForkchoiceState {
    fn to_json(&self) -> Json {
        object([
            ("headBlockHash", self.head_block_hash.to_json()),
            ("safeBlockHash", self.safe_block_hash.to_json()),
            ("finalizedBlockHash", self.finalized_block_hash.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            head_block_hash: fields.required("headBlockHash")?,
            safe_block_hash: fields.required("safeBlockHash")?,
            finalized_block_hash: fields.required("finalizedBlockHash")?,
        })
    }
}

/// What the engine should build on top of the head, for a proposer.
///
/// The consensus layer fills it from its state, as `prepare_execution_payload` does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadAttributes<P: Preset> {
    /// Timestamp of the slot the payload is for.
    pub timestamp: u64,

    /// Randao mix of the current epoch.
    pub prev_randao: Bytes32,

    /// Address to receive the fees, a suggestion the builder may override.
    pub suggested_fee_recipient: ExecutionAddress,

    /// Withdrawals the payload must contain, from the expected withdrawals sweep.
    pub withdrawals: Withdrawals<P>,

    /// Root of the beacon block the new block will build on, see EIP-4788.
    pub parent_beacon_block_root: Root,
}

impl<P: Preset> JsonCodec for PayloadAttributes<P> {
    fn to_json(&self) -> Json {
        object([
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

/// The engine's handle on a payload it is building.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PayloadId(pub [u8; 8]);

impl JsonCodec for PayloadId {
    fn to_json(&self) -> Json {
        Json::String(self.0.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        read_fixed(value).map(Self)
    }
}

impl fmt::Display for PayloadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_data())
    }
}

/// The engine's reply to a fork choice update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkchoiceUpdated {
    /// Validity of the new head.
    ///
    /// Only valid, invalid, and syncing occur here, per `src/engine/paris.md`.
    pub payload_status: PayloadStatus,

    /// The build that started, when attributes were given and the head is valid.
    pub payload_id: Option<PayloadId>,
}

impl JsonCodec for ForkchoiceUpdated {
    fn to_json(&self) -> Json {
        object([
            ("payloadStatus", self.payload_status.to_json()),
            ("payloadId", nullable(self.payload_id.as_ref())),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            payload_status: fields.required("payloadStatus")?,
            payload_id: fields.optional("payloadId")?,
        })
    }
}
