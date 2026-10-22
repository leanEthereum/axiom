//! Reasons a light client refuses a bootstrap or an update.

use thiserror::Error;

/// A bootstrap or update the light client cannot accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum LightClientError {
    /// A header's execution payload is not proven against its body.
    #[error("header execution payload is not proven")]
    InvalidHeader,
    /// The bootstrap header is not the trusted block.
    #[error("bootstrap header is not the trusted block")]
    UntrustedBootstrap,
    /// A merkle branch does not prove its leaf.
    #[error("merkle branch does not prove its leaf")]
    InvalidBranch,
    /// Too few sync committee members signed.
    #[error("too few sync committee members signed")]
    InsufficientParticipants,
    /// The update's slots are out of order or in the future.
    #[error("update slots are out of order or in the future")]
    InvalidSlots,
    /// The update skips a sync committee period.
    #[error("update skips a sync committee period")]
    SkippedPeriod,
    /// The update brings nothing new.
    #[error("update brings nothing new")]
    Irrelevant,
    /// A field that must be empty is not.
    #[error("a field that must be empty is not")]
    UnexpectedData,
    /// The update's next committee contradicts the known one.
    #[error("next committee contradicts the known one")]
    ConflictingCommittee,
    /// The sync committee signature does not verify.
    #[error("sync committee signature does not verify")]
    InvalidSignature,
}
