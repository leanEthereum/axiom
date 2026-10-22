//! The execution engine's verdict on a block's payload, as the fork choice consumes it.

use axiom_state_transition::{ExecutionEngine, KnownVerdict};
use axiom_types::Hash32;

/// The engine's answer to a new payload, simplified to what the fork choice needs.
///
/// See `PayloadStatusV1` in the execution API and the Bellatrix optimistic sync spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadStatus {
    /// The payload executed and is valid.
    Valid,
    /// The engine has not validated the payload yet, as with SYNCING or ACCEPTED.
    NotValidated,
    /// The payload, or an ancestor after the latest valid one, is invalid.
    Invalid {
        /// Hash of the latest valid ancestor's payload, when the engine knows it.
        latest_valid_hash: Option<Hash32>,
    },
}

impl PayloadStatus {
    /// Whether the block may be imported: valid or not yet known to be invalid.
    #[must_use]
    pub const fn is_importable(self) -> bool {
        !matches!(self, Self::Invalid { .. })
    }
}

impl<R> ExecutionEngine<R> for PayloadStatus {
    fn verify_and_notify_new_payload(&self, request: &R) -> bool {
        // An optimistic import treats a pending verdict as success.
        KnownVerdict(self.is_importable()).verify_and_notify_new_payload(request)
    }
}
