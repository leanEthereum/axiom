//! Protocol constants that no preset or configuration may change.
//!
//! Names follow the consensus specs, so a reader can search both side by side.

use crate::{BlsSignature, BuilderIndex, DomainType, Gwei};

/// Bits of justification history the state keeps, enough for the four finality rules.
///
/// See `weigh_justification_and_finalization` in the phase0 beacon chain spec.
pub const JUSTIFICATION_BITS_LENGTH: usize = 4;

/// Depth of the deposit contract's merkle tree, so it holds 2^32 deposits.
pub const DEPOSIT_CONTRACT_TREE_DEPTH: usize = 32;

/// Bytes of a BLS12-381 scalar field element in a blob.
pub const BYTES_PER_FIELD_ELEMENT: u64 = 32;

/// Sync committee subnets, which split the committee for gossip.
///
/// See the Altair validator spec.
pub const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;

/// Aggregators each committee aims for, so an aggregate survives a few offline ones.
pub const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;

/// Aggregators each sync subcommittee aims for.
pub const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: u64 = 16;

/// Withdrawal credential prefix of a key that can only sign, not receive funds.
pub const BLS_WITHDRAWAL_PREFIX: u8 = 0x00;

/// Withdrawal credential prefix of an execution address that receives withdrawals.
pub const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;

/// Withdrawal credential prefix of a compounding validator.
///
/// See EIP-7251.
pub const COMPOUNDING_WITHDRAWAL_PREFIX: u8 = 0x02;

/// Withdrawal credential prefix of a builder, whose deposits join the builder registry.
///
/// See EIP-7732 and the Gloas beacon chain spec.
pub const BUILDER_WITHDRAWAL_PREFIX: u8 = 0xb0;

/// The compressed point at infinity of G2, a placeholder signature.
///
/// Stake moved between queues carries it, since its key was already proven.
/// See the Altair BLS extensions and `queue_excess_active_balance` in the Electra spec.
pub const G2_POINT_AT_INFINITY: BlsSignature = {
    let mut bytes = [0; 96];
    // The compression flag and the infinity flag, with every coordinate bit clear.
    bytes[0] = 0xc0;
    BlsSignature(bytes)
};

/// Version byte of a versioned hash that commits to a KZG commitment.
///
/// See EIP-4844.
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

/// Marks a state that has not yet seen its first deposit request.
///
/// See EIP-6110.
pub const UNSET_DEPOSIT_REQUESTS_START_INDEX: u64 = u64::MAX;

/// Withdrawal request amount that asks for a full exit rather than a partial withdrawal.
///
/// See EIP-7002.
pub const FULL_EXIT_REQUEST_AMOUNT: Gwei = Gwei(0);

/// Execution request type byte of deposit requests.
pub const DEPOSIT_REQUEST_TYPE: u8 = 0x00;

/// Execution request type byte of withdrawal requests.
pub const WITHDRAWAL_REQUEST_TYPE: u8 = 0x01;

/// Execution request type byte of consolidation requests.
pub const CONSOLIDATION_REQUEST_TYPE: u8 = 0x02;

/// Execution request type byte of builder deposit requests.
///
/// See EIP-7732 and the Gloas beacon chain spec.
pub const BUILDER_DEPOSIT_REQUEST_TYPE: u8 = 0x03;

/// Execution request type byte of builder exit requests.
///
/// See EIP-7732 and the Gloas beacon chain spec.
pub const BUILDER_EXIT_REQUEST_TYPE: u8 = 0x04;

/// Bit that marks a withdrawal's validator index as a builder index.
///
/// Builders and validators then share one withdrawal container.
/// It sits far above any registry size, so no validator index carries it.
/// See the Gloas beacon chain spec.
pub const BUILDER_INDEX_FLAG: u64 = 1 << 40;

/// Builder index a bid names when the proposer builds its own payload.
///
/// See the Gloas beacon chain spec.
pub const BUILDER_INDEX_SELF_BUILD: BuilderIndex = BuilderIndex(u64::MAX);

/// Numerator of the share of a slot's committees whose vote settles a builder payment.
///
/// Six tenths of the weight must attest the payload's block before its builder pays.
/// See `get_builder_payment_quorum_threshold` in the Gloas beacon chain spec.
pub const BUILDER_PAYMENT_THRESHOLD_NUMERATOR: u64 = 6;

/// Denominator of the builder payment threshold.
pub const BUILDER_PAYMENT_THRESHOLD_DENOMINATOR: u64 = 10;

/// Version of the builders a deposit registers.
///
/// See the Gloas beacon chain spec.
pub const PAYLOAD_BUILDER_VERSION: u8 = 0;

/// Flag index of a timely vote for the source checkpoint.
pub const TIMELY_SOURCE_FLAG_INDEX: usize = 0;

/// Flag index of a timely vote for the target checkpoint.
pub const TIMELY_TARGET_FLAG_INDEX: usize = 1;

/// Flag index of a timely vote for the head block.
pub const TIMELY_HEAD_FLAG_INDEX: usize = 2;

/// Reward weight of a timely source vote, out of the weight denominator.
pub const TIMELY_SOURCE_WEIGHT: u64 = 14;

/// Reward weight of a timely target vote, the heaviest since it drives finality.
pub const TIMELY_TARGET_WEIGHT: u64 = 26;

/// Reward weight of a timely head vote.
pub const TIMELY_HEAD_WEIGHT: u64 = 14;

/// Reward weight of sync committee participation.
pub const SYNC_REWARD_WEIGHT: u64 = 2;

/// Reward weight of the proposer's cut.
pub const PROPOSER_WEIGHT: u64 = 8;

/// Sum of all reward weights.
///
/// The weights above sum to 64, so the base reward splits exactly.
pub const WEIGHT_DENOMINATOR: u64 = 64;

/// Reward weights of the participation flags, in flag index order.
pub const PARTICIPATION_FLAG_WEIGHTS: [u64; 3] = [
    TIMELY_SOURCE_WEIGHT,
    TIMELY_TARGET_WEIGHT,
    TIMELY_HEAD_WEIGHT,
];

/// Domain of block proposals.
pub const DOMAIN_BEACON_PROPOSER: DomainType = DomainType([0x00, 0, 0, 0]);

/// Domain of attestations.
pub const DOMAIN_BEACON_ATTESTER: DomainType = DomainType([0x01, 0, 0, 0]);

/// Domain of randao reveals.
pub const DOMAIN_RANDAO: DomainType = DomainType([0x02, 0, 0, 0]);

/// Domain of deposits, which ignores the fork so deposits stay valid across forks.
pub const DOMAIN_DEPOSIT: DomainType = DomainType([0x03, 0, 0, 0]);

/// Domain of voluntary exits.
pub const DOMAIN_VOLUNTARY_EXIT: DomainType = DomainType([0x04, 0, 0, 0]);

/// Domain of aggregator selection proofs.
pub const DOMAIN_SELECTION_PROOF: DomainType = DomainType([0x05, 0, 0, 0]);

/// Domain of signed aggregates.
pub const DOMAIN_AGGREGATE_AND_PROOF: DomainType = DomainType([0x06, 0, 0, 0]);

/// Domain of sync committee messages.
pub const DOMAIN_SYNC_COMMITTEE: DomainType = DomainType([0x07, 0, 0, 0]);

/// Domain of sync aggregator selection proofs.
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: DomainType = DomainType([0x08, 0, 0, 0]);

/// Domain of signed sync contributions.
pub const DOMAIN_CONTRIBUTION_AND_PROOF: DomainType = DomainType([0x09, 0, 0, 0]);

/// Domain of withdrawal credential changes.
pub const DOMAIN_BLS_TO_EXECUTION_CHANGE: DomainType = DomainType([0x0a, 0, 0, 0]);

/// Domain of builder bids and payload envelopes.
///
/// See EIP-7732 and the Gloas beacon chain spec.
pub const DOMAIN_BEACON_BUILDER: DomainType = DomainType([0x0b, 0, 0, 0]);

/// Domain of payload timeliness attestations.
pub const DOMAIN_PTC_ATTESTER: DomainType = DomainType([0x0c, 0, 0, 0]);

/// Domain of proposer preferences.
pub const DOMAIN_PROPOSER_PREFERENCES: DomainType = DomainType([0x0d, 0, 0, 0]);

/// Domain of builder deposits.
pub const DOMAIN_BUILDER_DEPOSIT: DomainType = DomainType([0x0e, 0, 0, 0]);

/// Domain prefix reserved for applications built on beacon chain keys.
pub const DOMAIN_APPLICATION_MASK: DomainType = DomainType([0x00, 0, 0, 0x01]);

/// Domain of builder API messages, such as validator registrations.
///
/// It is the application mask itself, so no consensus message can collide with it.
/// See the Bellatrix builder spec in the builder-specs repository.
pub const DOMAIN_APPLICATION_BUILDER: DomainType = DOMAIN_APPLICATION_MASK;
