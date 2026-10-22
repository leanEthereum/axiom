//! Reasons a light client refuses a bootstrap or an update.

use std::{error::Error, fmt};

/// A bootstrap or update the light client cannot accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LightClientError {
    /// A header's execution payload is not proven against its body.
    InvalidHeader,
    /// The bootstrap header is not the trusted block.
    UntrustedBootstrap,
    /// A merkle branch does not prove its leaf.
    InvalidBranch,
    /// Too few sync committee members signed.
    InsufficientParticipants,
    /// The update's slots are out of order or in the future.
    InvalidSlots,
    /// The update skips a sync committee period.
    SkippedPeriod,
    /// The update brings nothing new.
    Irrelevant,
    /// A field that must be empty is not.
    UnexpectedData,
    /// The update's next committee contradicts the known one.
    ConflictingCommittee,
    /// The sync committee signature does not verify.
    InvalidSignature,
}

impl fmt::Display for LightClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidHeader => "header execution payload is not proven",
            Self::UntrustedBootstrap => "bootstrap header is not the trusted block",
            Self::InvalidBranch => "merkle branch does not prove its leaf",
            Self::InsufficientParticipants => "too few sync committee members signed",
            Self::InvalidSlots => "update slots are out of order or in the future",
            Self::SkippedPeriod => "update skips a sync committee period",
            Self::Irrelevant => "update brings nothing new",
            Self::UnexpectedData => "a field that must be empty is not",
            Self::ConflictingCommittee => "next committee contradicts the known one",
            Self::InvalidSignature => "sync committee signature does not verify",
        })
    }
}

impl Error for LightClientError {}
