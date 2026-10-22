//! Reasons light client data is refused, or cannot be created.

use axiom_bls::BlsError;
use axiom_ssz::{DecodeError, Root};
use axiom_types::{ForkName, Slot};
use thiserror::Error;

/// A bootstrap or update the light client cannot accept, or a full node cannot create.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
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
    /// A branch holds more nodes than its fork's branch type.
    #[error("branch of {length} nodes exceeds the {capacity} its type holds")]
    BranchTooLong {
        /// Nodes in the branch.
        length: usize,
        /// Nodes the branch type holds.
        capacity: usize,
    },
    /// Light client data comes from a later fork than the store.
    #[error("{data} light client data cannot enter a {store} store before the store upgrades")]
    LaterData {
        /// Fork whose format the data has.
        data: ForkName,
        /// Fork whose format the store has.
        store: ForkName,
    },
    /// Bytes do not decode as light client data of a fork.
    #[error("bytes are not {fork} light client data: {source}")]
    Decode {
        /// The fork whose format the bytes claim.
        fork: ForkName,
        /// Why decoding failed.
        #[source]
        source: DecodeError,
    },
    /// A fork defines no light client data.
    #[error("{0} defines no light client data")]
    NoLightClientData(ForkName),
    /// Two headers that must share a format do not.
    #[error("attested header has the {attested} format, finalized header the {finalized} format")]
    MixedHeaders {
        /// Format of the attested header.
        attested: ForkName,
        /// Format of the finalized header.
        finalized: ForkName,
    },
    /// A state has advanced past the block it should be the post-state of.
    #[error("state at slot {state} has advanced past its latest block at slot {block}")]
    StateAdvanced {
        /// The state's slot.
        state: Slot,
        /// Slot of the state's latest block header.
        block: Slot,
    },
    /// A state is the post-state of another block than the one given.
    #[error("state is the post-state of block {state}, not of block {block}")]
    NotPostState {
        /// Root of the block the state follows.
        state: Root,
        /// Root of the block given with it.
        block: Root,
    },
    /// The signature block does not build on the attested block.
    #[error("signature block has parent {parent}, not the attested block {attested}")]
    NotParent {
        /// Parent root of the signature block.
        parent: Root,
        /// Root of the attested block.
        attested: Root,
    },
    /// The finalized block is not the one the attested state finalized.
    #[error("attested state finalized {checkpoint}, but the finalized block stands for {block}")]
    FinalizedMismatch {
        /// Finalized checkpoint root in the attested state.
        checkpoint: Root,
        /// Root the finalized block stands for, zero for the genesis block.
        block: Root,
    },
    /// A state's tree has no node where its fork's layout places a proven field.
    #[error("{fork} state has no node at generalized index {gindex}")]
    MissingNode {
        /// Fork of the state.
        fork: ForkName,
        /// Position of the missing node.
        gindex: u64,
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

/// Why a full node ignores a light client update on gossip, rather than forwarding it.
///
/// Every outcome here is an ignore: an honest but slow or early peer may send it.
/// See the `light_client_finality_update` and `light_client_optimistic_update` topics.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum GossipIgnore {
    /// The update is not the one the node computed from its own chain.
    #[error("update attested at slot {attested} is not the one computed locally")]
    NotLocal {
        /// Slot of the update's attested header.
        attested: Slot,
    },
    /// The signature block has not had time to propagate.
    #[error("update arrived at {now_ms} ms, before the earliest allowed {earliest_ms} ms")]
    Early {
        /// Arrival time, in milliseconds since the Unix epoch.
        now_ms: u64,
        /// Signature slot start plus the sync message due time, less the clock disparity.
        earliest_ms: u64,
    },
    /// A finality update for this finalized slot, or a later one, was already forwarded.
    #[error("finalized slot {finalized} does not advance past the forwarded slot {forwarded}")]
    StaleFinality {
        /// Slot of the update's finalized header.
        finalized: Slot,
        /// Highest finalized slot forwarded so far.
        forwarded: Slot,
    },
    /// An optimistic update for this attested slot, or a later one, was already forwarded.
    #[error("attested slot {attested} does not advance past the forwarded slot {forwarded}")]
    StaleOptimistic {
        /// Slot of the update's attested header.
        attested: Slot,
        /// Highest attested slot forwarded so far.
        forwarded: Slot,
    },
}
