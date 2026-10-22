//! The reply to eth_syncing.
//!
//! Defined by the execution JSON-RPC spec, `src/eth/client.yaml` in execution-apis.
//!
//! ```text
//!     false                                                      in sync
//!     {"startingBlock":"0x0","currentBlock":"0x1","highestBlock":"0x9"}   syncing
//! ```

use axiom_json::Json;

use super::{Fields, JsonCodec, object, wrong_type};
use crate::WireError;

/// Whether the execution client is still catching up with the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SyncStatus {
    /// The client follows the head.
    Synced,

    /// The client is importing blocks.
    Syncing {
        /// Block where this sync began.
        starting_block: u64,
        /// Block imported last.
        current_block: u64,
        /// Highest block the client knows of.
        highest_block: u64,
    },
}

impl JsonCodec for SyncStatus {
    fn to_json(&self) -> Json {
        match self {
            Self::Synced => Json::Bool(false),
            Self::Syncing {
                starting_block,
                current_block,
                highest_block,
            } => object([
                ("startingBlock", starting_block.to_json()),
                ("currentBlock", current_block.to_json()),
                ("highestBlock", highest_block.to_json()),
            ]),
        }
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        // Only false means synced; true is not a defined reply.
        match value {
            Json::Bool(false) => Ok(Self::Synced),
            Json::Object(_) => {
                // Clients add members such as healedBytecodes; only the three standard ones are read.
                let fields = Fields::of(value)?;
                Ok(Self::Syncing {
                    starting_block: fields.required("startingBlock")?,
                    current_block: fields.required("currentBlock")?,
                    highest_block: fields.required("highestBlock")?,
                })
            }
            other => Err(wrong_type("false or object", other)),
        }
    }
}
