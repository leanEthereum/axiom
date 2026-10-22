//! Why slashing protection refused a message, or could not decide.

use axiom_json::{HexError, ParseError};
use axiom_store::Error as StoreError;
use axiom_types::{BlsPubkey, Epoch, Root, Slot};
use thiserror::Error;

/// A message slashing protection refuses to let a key sign.
///
/// Each variant names the record the message conflicts with.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Refusal {
    /// The key is not registered with the database.
    #[error("validator {pubkey} is not registered for slashing protection")]
    Unregistered {
        /// The key asked to sign.
        pubkey: BlsPubkey,
    },
    /// A different block, or one of unknown root, was signed at the slot.
    #[error("double proposal by {pubkey} at slot {slot}: recorded {recorded:?}, asked {asked:?}")]
    DoubleProposal {
        /// The proposer.
        pubkey: BlsPubkey,
        /// The slot of both blocks.
        slot: Slot,
        /// Signing root of the recorded block, unknown for some imports.
        recorded: Option<Root>,
        /// Signing root of the new block, unknown for some imports.
        asked: Option<Root>,
    },
    /// The slot does not come after the latest recorded block.
    #[error("block by {pubkey} at slot {slot} does not follow the latest block at slot {latest}")]
    BlockNotAfterLatest {
        /// The proposer.
        pubkey: BlsPubkey,
        /// The slot of the new block.
        slot: Slot,
        /// The slot of the latest recorded block.
        latest: Slot,
    },
    /// The vote's source comes after its target.
    #[error("vote by {pubkey} has source {source_epoch} after target {target_epoch}")]
    SourceAfterTarget {
        /// The attester.
        pubkey: BlsPubkey,
        /// Source epoch.
        source_epoch: Epoch,
        /// Target epoch.
        target_epoch: Epoch,
    },
    /// A different vote, or one of unknown root, was signed for the target.
    #[error(
        "double vote by {pubkey} for target {target_epoch}: recorded {recorded:?}, asked {asked:?}"
    )]
    DoubleVote {
        /// The attester.
        pubkey: BlsPubkey,
        /// The target epoch of both votes.
        target_epoch: Epoch,
        /// Signing root of the recorded vote, unknown for some imports.
        recorded: Option<Root>,
        /// Signing root of the new vote, unknown for some imports.
        asked: Option<Root>,
    },
    /// A recorded vote strictly surrounds the new one.
    #[error(
        "vote by {pubkey} from {source_epoch} to {target_epoch} is surrounded by {recorded_source} to {recorded_target}"
    )]
    Surrounded {
        /// The attester.
        pubkey: BlsPubkey,
        /// Source of the new vote.
        source_epoch: Epoch,
        /// Target of the new vote.
        target_epoch: Epoch,
        /// Source of the recorded vote.
        recorded_source: Epoch,
        /// Target of the recorded vote.
        recorded_target: Epoch,
    },
    /// The new vote strictly surrounds a recorded one.
    #[error(
        "vote by {pubkey} from {source_epoch} to {target_epoch} surrounds {recorded_source} to {recorded_target}"
    )]
    Surrounding {
        /// The attester.
        pubkey: BlsPubkey,
        /// Source of the new vote.
        source_epoch: Epoch,
        /// Target of the new vote.
        target_epoch: Epoch,
        /// Source of the recorded vote.
        recorded_source: Epoch,
        /// Target of the recorded vote.
        recorded_target: Epoch,
    },
    /// The source falls behind the highest recorded source.
    #[error("vote by {pubkey} has source {source_epoch} behind the latest source {latest}")]
    SourceBeforeLatest {
        /// The attester.
        pubkey: BlsPubkey,
        /// Source of the new vote.
        source_epoch: Epoch,
        /// The highest recorded source.
        latest: Epoch,
    },
    /// The target does not come after the latest recorded target.
    #[error("vote by {pubkey} has target {target_epoch}, not after the latest target {latest}")]
    TargetNotAfterLatest {
        /// The attester.
        pubkey: BlsPubkey,
        /// Target of the new vote.
        target_epoch: Epoch,
        /// The highest recorded target.
        latest: Epoch,
    },
}

/// Why slashing protection failed.
#[derive(Debug, Error)]
pub enum ProtectionError {
    /// The message would be slashable, or protection cannot vouch for it.
    #[error(transparent)]
    Refused(Box<Refusal>),
    /// The database belongs to another chain.
    #[error("database is for genesis validators root {expected}, not {actual}")]
    WrongChain {
        /// Root the database was created for.
        expected: Root,
        /// Root of the request or interchange.
        actual: Root,
    },
    /// The interchange holds data slashable against itself or the database.
    #[error("interchange is slashable: {0}")]
    SlashableImport(#[source] Box<Refusal>),
    /// A stored record does not have its expected size.
    #[error("corrupt {table} record of {len} bytes")]
    Corrupt {
        /// The table holding it.
        table: &'static str,
        /// Bytes found.
        len: usize,
    },
    /// The store failed.
    #[error("slashing protection store: {0}")]
    Store(#[from] StoreError),
}

impl From<Refusal> for ProtectionError {
    fn from(refusal: Refusal) -> Self {
        // A refusal names two roots and a key; boxing keeps every result small.
        Self::Refused(Box::new(refusal))
    }
}

/// Why an interchange document cannot be read.
#[derive(Debug, Error)]
pub enum InterchangeError {
    /// The text is not JSON.
    #[error("interchange is not JSON: {0}")]
    Json(#[from] ParseError),
    /// A required field is missing or has the wrong JSON type.
    #[error("interchange field {field} is missing or not {expected}")]
    Field {
        /// The field's name.
        field: &'static str,
        /// The JSON type it must have.
        expected: &'static str,
    },
    /// The format version is not the one this client reads.
    #[error("interchange format version {found}, expected {expected}")]
    Version {
        /// Version in the document.
        found: String,
        /// Version supported.
        expected: &'static str,
    },
    /// A hex field does not decode.
    #[error("interchange field {field} is not valid hex: {source}")]
    Hex {
        /// The field's name.
        field: &'static str,
        /// What is wrong with the digits.
        #[source]
        source: HexError,
    },
    /// A number is not a decimal integer in range.
    #[error("interchange field {field} is not a decimal u64: {value}")]
    Number {
        /// The field's name.
        field: &'static str,
        /// The text found.
        value: String,
    },
}
