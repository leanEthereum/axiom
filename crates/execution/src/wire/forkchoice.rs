//! Fork choice updates: the state and the reply.
//!
//! Both are defined in `src/engine/paris.md`, and every later version keeps them.
//!
//! ```text
//!     ForkchoiceStateV1     headBlockHash, safeBlockHash, finalizedBlockHash   DATA 32 each
//!     reply                 payloadStatus          PayloadStatusV1
//!                           payloadId              DATA 8 or null
//! ```

use std::fmt;

use axiom_json::{Data, Json};
use axiom_types::Hash32;

use super::{Fields, JsonCodec, PayloadStatus, Reader};
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
        Json::from([
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

/// The engine's handle on a payload it is building.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PayloadId(pub [u8; 8]);

impl JsonCodec for PayloadId {
    fn to_json(&self) -> Json {
        Json::String(self.0.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        Reader::new(value).data().map(Self)
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
        Json::from([
            ("payloadStatus", self.payload_status.to_json()),
            ("payloadId", self.payload_id.to_json()),
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::PayloadStatusKind;

    proptest! {
        #[test]
        fn state_and_reply_round_trip(hashes in any::<[[u8; 32]; 3]>(), id in any::<Option<[u8; 8]>>()) {
            let state = ForkchoiceState {
                head_block_hash: Hash32(hashes[0]),
                safe_block_hash: Hash32(hashes[1]),
                finalized_block_hash: Hash32(hashes[2]),
            };
            prop_assert_eq!(ForkchoiceState::from_json(&state.to_json()), Ok(state));

            let reply = ForkchoiceUpdated {
                payload_status: PayloadStatus {
                    status: PayloadStatusKind::Valid,
                    latest_valid_hash: Some(state.head_block_hash),
                    validation_error: None,
                },
                payload_id: id.map(PayloadId),
            };
            prop_assert_eq!(ForkchoiceUpdated::from_json(&reply.to_json()), Ok(reply));
        }
    }
}
