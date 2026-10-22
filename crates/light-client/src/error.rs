//! Reasons a light client refuses a bootstrap or an update.

use axiom_bls::BlsError;
use axiom_ssz::Root;
use axiom_types::Slot;
use thiserror::Error;

/// A bootstrap or update the light client cannot accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum LightClientError {
    /// A header's execution payload is not proven against its body.
    #[error("execution payload of the header at slot {0} is not proven")]
    InvalidHeader(Slot),
    /// The bootstrap header is not the trusted block.
    #[error("bootstrap header {header} is not the trusted block {trusted}")]
    UntrustedBootstrap {
        /// Root of the bootstrap header.
        header: Root,
        /// The block root the client trusts.
        trusted: Root,
    },
    /// A merkle branch does not prove its leaf.
    #[error("branch at generalized index {gindex} does not prove its leaf under root {root}")]
    InvalidBranch {
        /// Position of the leaf in the tree.
        gindex: u64,
        /// The root the branch must reach.
        root: Root,
    },
    /// Too few sync committee members signed.
    #[error("{participants} sync committee members signed, below the minimum of {minimum}")]
    InsufficientParticipants {
        /// Members that signed.
        participants: u64,
        /// The fewest signers an update may have.
        minimum: u64,
    },
    /// The update's slots are out of order or in the future.
    #[error(
        "update slots are out of order or in the future: current {current}, signature {signature}, attested {attested}, finalized {finalized}"
    )]
    InvalidSlots {
        /// The client's current slot.
        current: Slot,
        /// The slot of the sync committee signature.
        signature: Slot,
        /// The slot of the attested header.
        attested: Slot,
        /// The slot of the finalized header.
        finalized: Slot,
    },
    /// The update skips a sync committee period.
    #[error("update period {period} does not follow store period {store_period}")]
    SkippedPeriod {
        /// The sync committee period of the update.
        period: u64,
        /// The sync committee period of the store's finalized header.
        store_period: u64,
    },
    /// The update brings nothing new.
    #[error("update attested at slot {attested} brings nothing past finalized slot {finalized}")]
    Irrelevant {
        /// The slot of the update's attested header.
        attested: Slot,
        /// The slot of the store's finalized header.
        finalized: Slot,
    },
    /// A field that must be empty is not.
    #[error("update field {0} must be empty")]
    UnexpectedData(&'static str),
    /// The update's next committee contradicts the known one.
    #[error("next committee of period {0} contradicts the known one")]
    ConflictingCommittee(u64),
    /// A committee key does not decompress.
    #[error("sync committee key at seat {seat} does not decompress: {source}")]
    MalformedCommitteeKey {
        /// Position of the key in the committee.
        seat: usize,
        /// Why the bytes are not a key.
        #[source]
        source: BlsError,
    },
    /// The sync committee signature does not decompress.
    #[error("sync committee signature does not decompress: {0}")]
    MalformedSignature(#[source] BlsError),
    /// The sync committee signature does not verify.
    #[error(
        "sync committee signature of slot {signature_slot} by {participants} members does not verify"
    )]
    InvalidSignature {
        /// The slot of the signature.
        signature_slot: Slot,
        /// Members whose keys the signature is checked against.
        participants: usize,
    },
}
