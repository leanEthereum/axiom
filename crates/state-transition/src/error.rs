//! Reasons a state transition fails.
//!
//! A block that breaks a rule is invalid, and the node discards it.
//! A state that breaks an invariant is corrupt, which a valid chain never produces.

use axiom_bls::BlsError;
use axiom_ssz::CapacityError;
use axiom_types::{
    Bytes32, Checkpoint, CommitteeIndex, Epoch, Hash32, Root, Slot, ValidatorIndex,
};
use thiserror::Error;

/// A state that violates an invariant the protocol relies on.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum StateError {
    /// A validator index points past the registry.
    #[error("validator {index} is not in the registry of {registry_size}")]
    UnknownValidator {
        /// The index asked for.
        index: ValidatorIndex,
        /// Validators in the registry, one more than the largest valid index.
        registry_size: usize,
    },
    /// A registry key does not decompress to a curve point.
    ///
    /// Deposits prove possession of their key, so a valid chain never registers such a key.
    #[error("key of validator {0} does not decompress")]
    MalformedPublicKey(ValidatorIndex),
    /// A sync committee seat holds a key the registry does not know.
    #[error("sync committee seat {seat} holds a key outside the registry")]
    UnknownSyncCommitteeMember {
        /// Position of the seat in the committee.
        seat: usize,
    },
    /// A block root was read outside the window the state keeps.
    #[error("block root of slot {slot} is not kept at slot {state_slot}")]
    BlockRootOutOfRange {
        /// The slot asked for.
        slot: Slot,
        /// The state's slot.
        state_slot: Slot,
    },
    /// Committees were asked for an epoch other than the previous, current, or next one.
    #[error("committees of epoch {epoch} are not known at epoch {current}")]
    EpochOutOfRange {
        /// The epoch asked for.
        epoch: Epoch,
        /// The state's epoch.
        current: Epoch,
    },
    /// An epoch has no active validator, so no committee or proposer exists.
    #[error("epoch {0} has no active validator")]
    NoActiveValidators(Epoch),
    /// A balance, epoch, or counter left the range of 64 bits.
    #[error("{quantity} overflows 64 bits")]
    Overflow {
        /// What was computed, such as the slashed total.
        quantity: &'static str,
    },
    /// A list does not fit the bound its SSZ type sets.
    #[error("{list} does not fit: {source}")]
    Capacity {
        /// The list, such as the pending deposits.
        list: &'static str,
        /// The bound and the length that broke it.
        #[source]
        source: CapacityError,
    },
    /// Slot processing was asked to go backwards or stand still.
    #[error("target slot {target} is not after state slot {state_slot}")]
    SlotNotInFuture {
        /// The target slot.
        target: Slot,
        /// The state's slot.
        state_slot: Slot,
    },
    /// The keys of a sync committee do not aggregate.
    #[error("sync committee keys do not aggregate: {0}")]
    InvalidSyncCommittee(#[source] BlsError),
    /// The aggregate key a sync committee stores does not decompress.
    #[error("sync committee aggregate key does not decompress: {0}")]
    MalformedSyncCommitteeKey(#[source] BlsError),
}

/// A block that breaks a rule of block processing.
///
/// Each variant names the assertion of the spec that failed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BlockError {
    /// The block's slot is not the state's slot.
    #[error("block slot {block} is not state slot {state}")]
    SlotMismatch {
        /// The block's slot.
        block: Slot,
        /// The state's slot.
        state: Slot,
    },
    /// The block is not newer than the latest block.
    #[error("block slot {block} is not after latest block slot {latest}")]
    NotNewerThanParent {
        /// The block's slot.
        block: Slot,
        /// Slot of the latest block header.
        latest: Slot,
    },
    /// The block names the wrong proposer.
    #[error("block names proposer {claimed}, slot proposer is {expected}")]
    WrongProposer {
        /// The proposer the block names.
        claimed: ValidatorIndex,
        /// The proposer of the slot.
        expected: ValidatorIndex,
    },
    /// The block's parent is not the latest block.
    #[error("block parent {claimed} is not the latest block {expected}")]
    ParentMismatch {
        /// The parent the block names.
        claimed: Root,
        /// Root of the latest block header.
        expected: Root,
    },
    /// The proposer was slashed.
    #[error("proposer {0} is slashed")]
    ProposerSlashed(ValidatorIndex),
    /// A signature is not a valid BLS signature encoding.
    #[error("signature over signing root {root} is malformed: {source}")]
    MalformedSignature {
        /// The signing root the signature covers, which names the object and its domain.
        root: Root,
        /// Why the bytes are not a signature.
        #[source]
        source: BlsError,
    },
    /// The keys of a signature's signers do not aggregate.
    #[error("signer keys do not aggregate: {0}")]
    InvalidAggregateKey(#[source] BlsError),
    /// A signature does not verify.
    ///
    /// Signatures are checked as one batch, so the failing one is not singled out.
    #[error("{signatures} signatures checked together, at least one fails")]
    InvalidSignature {
        /// Signatures in the failing batch.
        signatures: usize,
    },
    /// The withdrawals in the payload are not the expected ones.
    #[error(
        "payload carries {actual} withdrawals, {expected} expected, first difference at position {first_difference}"
    )]
    WithdrawalsMismatch {
        /// Withdrawals the state expects.
        expected: usize,
        /// Withdrawals the payload carries.
        actual: usize,
        /// Position of the first withdrawal that differs, or the shorter length.
        first_difference: usize,
    },
    /// The payload does not build on the latest payload.
    #[error("payload parent {claimed} is not the latest payload {expected}")]
    PayloadParentMismatch {
        /// The parent hash the payload names.
        claimed: Hash32,
        /// Block hash of the latest payload.
        expected: Hash32,
    },
    /// The payload's randomness is not the current randao mix.
    #[error("payload randomness {claimed} is not the randao mix {expected}")]
    PayloadRandaoMismatch {
        /// The randomness the payload carries.
        claimed: Bytes32,
        /// The state's randao mix of the current epoch.
        expected: Bytes32,
    },
    /// The payload's timestamp does not match the slot.
    #[error("payload timestamp {claimed} is not the slot time {expected}")]
    PayloadTimestampMismatch {
        /// The timestamp the payload carries, in seconds.
        claimed: u64,
        /// Start of the slot, in seconds since the Unix epoch.
        expected: u64,
    },
    /// The block carries more blobs than the schedule allows.
    #[error("{count} blob commitments exceed the limit of {limit}")]
    TooManyBlobs {
        /// Commitments in the block.
        count: usize,
        /// The limit at this epoch.
        limit: u64,
    },
    /// The execution engine rejected the payload.
    #[error("the execution engine rejected payload {0}")]
    PayloadInvalid(Hash32),
    /// The block carries deposits, which Fulu removed.
    #[error("block carries {0} deposits")]
    DepositsNotAllowed(usize),
    /// A proposer slashing does not show two distinct headers from one slot and proposer.
    #[error("proposer slashing of validator {proposer} is invalid: {reason}")]
    InvalidProposerSlashing {
        /// The proposer the first header names.
        proposer: ValidatorIndex,
        /// The rule the slashing breaks.
        reason: &'static str,
    },
    /// An attester slashing does not show a slashable pair of votes.
    #[error("votes with targets {first_target} and {second_target} are not slashable")]
    AttestationsNotSlashable {
        /// Target epoch of the first vote.
        first_target: Epoch,
        /// Target epoch of the second vote.
        second_target: Epoch,
    },
    /// An indexed attestation has no attesting index.
    #[error("attesting indices are empty")]
    EmptyAttestingIndices,
    /// An indexed attestation's indices are not strictly increasing.
    #[error("attesting index {index} at position {position} does not exceed its predecessor")]
    UnsortedAttestingIndices {
        /// Position of the first index out of order.
        position: usize,
        /// The index at that position.
        index: ValidatorIndex,
    },
    /// An attester slashing slashed nobody.
    #[error("none of {common} validators in both votes is slashable")]
    NoValidatorSlashed {
        /// Validators that signed both votes.
        common: usize,
    },
    /// An attestation's target is neither the previous nor the current epoch.
    #[error("attestation target epoch {target} is not previous or current at epoch {current}")]
    AttestationTargetEpochOutOfRange {
        /// The attestation's target epoch.
        target: Epoch,
        /// The state's epoch.
        current: Epoch,
    },
    /// An attestation's target epoch is not the epoch of its slot.
    #[error("attestation target epoch {target} is not the epoch of slot {slot}")]
    AttestationTargetSlotMismatch {
        /// The attestation's target epoch.
        target: Epoch,
        /// The attestation's slot.
        slot: Slot,
    },
    /// An attestation is included before its slot plus the inclusion delay.
    #[error("attestation of slot {slot} is included too early at slot {state_slot}")]
    AttestationTooEarly {
        /// The attestation's slot.
        slot: Slot,
        /// The slot of the including block.
        state_slot: Slot,
    },
    /// An attestation sets the committee index field, which Electra retired.
    #[error("attestation committee index {0} is not zero")]
    AttestationIndexNotZero(CommitteeIndex),
    /// An attestation names a committee that does not exist.
    #[error("committee {index} does not exist at slot {slot}, which has {committees_per_slot}")]
    UnknownCommittee {
        /// The attestation's slot.
        slot: Slot,
        /// The committee index named.
        index: CommitteeIndex,
        /// Committees in each slot of the epoch.
        committees_per_slot: u64,
    },
    /// An attestation has a committee with no participant.
    #[error("committee {index} at slot {slot} has no participant")]
    EmptyCommittee {
        /// The attestation's slot.
        slot: Slot,
        /// The committee index.
        index: CommitteeIndex,
    },
    /// An attestation's bitfield length is not the size of its committees.
    #[error("{actual} aggregation bits do not match {expected} committee members")]
    AggregationBitsLengthMismatch {
        /// Members of the selected committees together.
        expected: usize,
        /// Bits in the aggregation bitfield.
        actual: usize,
    },
    /// An attestation's source is not the justified checkpoint.
    #[error(
        "attestation source {}/{} is not the justified checkpoint {}/{}",
        .claimed.epoch, .claimed.root, .justified.epoch, .justified.root
    )]
    AttestationSourceMismatch {
        /// The source the attestation votes for.
        claimed: Checkpoint,
        /// The justified checkpoint of the target's epoch.
        justified: Checkpoint,
    },
    /// A voluntary exit breaks one of its rules.
    #[error("voluntary exit of validator {validator}: {reason}")]
    InvalidVoluntaryExit {
        /// The exiting validator.
        validator: ValidatorIndex,
        /// The rule the exit breaks.
        reason: &'static str,
    },
    /// A credential change breaks one of its rules.
    #[error("credential change of validator {validator}: {reason}")]
    InvalidCredentialChange {
        /// The validator whose credentials change.
        validator: ValidatorIndex,
        /// The rule the change breaks.
        reason: &'static str,
    },
    /// A state invariant broke while processing.
    #[error("state invariant broke: {0}")]
    State(#[from] StateError),
}

/// A full transition from a signed block that failed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TransitionError {
    /// Advancing through the empty slots failed.
    #[error("advancing to slot {target} failed: {source}")]
    Slots {
        /// The slot of the block being applied.
        target: Slot,
        /// The broken invariant.
        #[source]
        source: StateError,
    },
    /// The block is invalid.
    #[error("block at slot {slot} is invalid: {source}")]
    Block {
        /// The block's slot.
        slot: Slot,
        /// The rule the block breaks.
        #[source]
        source: BlockError,
    },
    /// The block's state root does not match the post-state.
    #[error("block claims state root {claimed}, post-state root is {computed}")]
    StateRootMismatch {
        /// Root the block claims.
        claimed: Root,
        /// Root of the computed post-state.
        computed: Root,
    },
}
