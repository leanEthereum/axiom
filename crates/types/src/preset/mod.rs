//! Presets: the compile-time constants that shape the protocol's types.
//!
//! The spec ships two presets.
//! Mainnet is the real chain, and minimal shrinks committees and epochs so tests run fast.
//!
//! Values come from `presets/{mainnet,minimal}/*.yaml` in the consensus specs.

mod mainnet;
mod minimal;

use std::{fmt::Debug, hash::Hash};

use axiom_ssz::Length;
pub use mainnet::Mainnet;
pub use minimal::Minimal;

use crate::Gwei;

/// A set of compile-time protocol constants.
///
/// A preset is a type, so a mainnet state and a minimal state are distinct types.
/// Mixing them is a compile error rather than a consensus bug.
///
/// Constants that size an SSZ collection also appear as a length type.
/// A unit test checks that each length type agrees with its constant.
pub trait Preset: Copy + Debug + Default + Eq + Hash + Send + Sync + 'static {
    /// The preset's name, as the spec's test vectors spell it.
    const NAME: &'static str;

    /// Upper bound on committees per slot, which caps attestation aggregation width.
    const MAX_COMMITTEES_PER_SLOT: u64;

    /// Committee size the shuffling aims for, chosen for a negligible chance of a dishonest majority.
    const TARGET_COMMITTEE_SIZE: u64;

    /// Upper bound on committee size, which sizes the aggregation bitfields.
    const MAX_VALIDATORS_PER_COMMITTEE: u64;

    /// Swap-or-not rounds, enough for the shuffle to be indistinguishable from random.
    const SHUFFLE_ROUND_COUNT: u64;

    /// Divides one increment into the hysteresis unit for effective balance updates.
    const HYSTERESIS_QUOTIENT: u64;

    /// Hysteresis units a balance must drop below the effective balance before it is lowered.
    const HYSTERESIS_DOWNWARD_MULTIPLIER: u64;

    /// Hysteresis units a balance must rise above the effective balance before it is raised.
    const HYSTERESIS_UPWARD_MULTIPLIER: u64;

    /// Smallest deposit accepted, which keeps the deposit queue from filling with dust.
    const MIN_DEPOSIT_AMOUNT: Gwei;

    /// Effective balance cap of a validator without compounding credentials before Electra.
    const MAX_EFFECTIVE_BALANCE: Gwei;

    /// Granularity of effective balances, so rewards are computed on whole ether.
    const EFFECTIVE_BALANCE_INCREMENT: Gwei;

    /// Slots an attestation must wait before inclusion, so it can propagate first.
    const MIN_ATTESTATION_INCLUSION_DELAY: u64;

    /// Slots per epoch, which sets how often committees and checkpoints turn over.
    const SLOTS_PER_EPOCH: u64;

    /// Epochs between a randao mix and the committees it seeds, so proposers cannot grind it live.
    const MIN_SEED_LOOKAHEAD: u64;

    /// Epochs an exit or activation is delayed, bounding how far ahead committees can be biased.
    const MAX_SEED_LOOKAHEAD: u64;

    /// Epochs in an eth1 data voting period, long enough to ride out execution reorgs.
    const EPOCHS_PER_ETH1_VOTING_PERIOD: u64;

    /// Epochs without finality after which the inactivity leak starts.
    const MIN_EPOCHS_TO_INACTIVITY_PENALTY: u64;

    /// Recent block and state roots kept in the state, about 27 hours on mainnet.
    const SLOTS_PER_HISTORICAL_ROOT: u64;

    /// Randao mixes kept in the state, which bounds how far back a seed can be read.
    const EPOCHS_PER_HISTORICAL_VECTOR: u64;

    /// Epochs over which slashed balances accumulate for the correlation penalty.
    const EPOCHS_PER_SLASHINGS_VECTOR: u64;

    /// Capacity of the historical summaries, enough for centuries of history.
    const HISTORICAL_ROOTS_LIMIT: u64;

    /// Capacity of the validator registry, which fixes the depth of its merkle tree.
    const VALIDATOR_REGISTRY_LIMIT: u64;

    /// Scales the base reward, and through it every reward and penalty.
    const BASE_REWARD_FACTOR: u64;

    /// Divides a slashed balance into the whistleblower reward before Electra.
    const WHISTLEBLOWER_REWARD_QUOTIENT: u64;

    /// Divides an attestation reward into the proposer's share before Altair.
    const PROPOSER_REWARD_QUOTIENT: u64;

    /// Inactivity leak quotient of phase0.
    const INACTIVITY_PENALTY_QUOTIENT: u64;

    /// Initial slashing penalty quotient of phase0.
    const MIN_SLASHING_PENALTY_QUOTIENT: u64;

    /// Correlation penalty multiplier of phase0.
    const PROPORTIONAL_SLASHING_MULTIPLIER: u64;

    /// Proposer slashings per block.
    const MAX_PROPOSER_SLASHINGS: u64;

    /// Attester slashings per block before Electra.
    const MAX_ATTESTER_SLASHINGS: u64;

    /// Attestations per block before Electra.
    const MAX_ATTESTATIONS: u64;

    /// Deposits per block.
    const MAX_DEPOSITS: u64;

    /// Voluntary exits per block.
    const MAX_VOLUNTARY_EXITS: u64;

    /// Inactivity leak quotient of Altair.
    const INACTIVITY_PENALTY_QUOTIENT_ALTAIR: u64;

    /// Initial slashing penalty quotient of Altair.
    const MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR: u64;

    /// Correlation penalty multiplier of Altair.
    const PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR: u64;

    /// Validators in a sync committee, large enough that a light client can trust a 2/3 majority.
    const SYNC_COMMITTEE_SIZE: u64;

    /// Epochs a sync committee serves, about 27 hours on mainnet.
    const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64;

    /// Signers a light client update needs to be considered at all.
    const MIN_SYNC_COMMITTEE_PARTICIPANTS: u64;

    /// Slots after which a light client force-updates without finality.
    const UPDATE_TIMEOUT: u64;

    /// Inactivity leak quotient from Bellatrix on, set so a leak halves a stake in about 18 days.
    const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: u64;

    /// Initial slashing penalty quotient of Bellatrix.
    const MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX: u64;

    /// Correlation penalty multiplier from Bellatrix on, so a one-third attack loses everything.
    const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64;

    /// Bytes per execution transaction.
    const MAX_BYTES_PER_TRANSACTION: u64;

    /// Transactions per execution payload.
    const MAX_TRANSACTIONS_PER_PAYLOAD: u64;

    /// Size of the execution logs bloom filter.
    const BYTES_PER_LOGS_BLOOM: u64;

    /// Size limit of the execution block's extra data.
    const MAX_EXTRA_DATA_BYTES: u64;

    /// Credential changes per block.
    const MAX_BLS_TO_EXECUTION_CHANGES: u64;

    /// Withdrawals per execution payload.
    const MAX_WITHDRAWALS_PER_PAYLOAD: u64;

    /// Validators the withdrawal sweep inspects per block, bounding its cost.
    const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64;

    /// Blob commitments a block can carry, which sizes the commitment list.
    const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64;

    /// Depth of a single commitment's proof inside a block body.
    const KZG_COMMITMENT_INCLUSION_PROOF_DEPTH: u64;

    /// Field elements in a blob, the degree bound of its polynomial.
    const FIELD_ELEMENTS_PER_BLOB: u64;

    /// Balance needed to activate, and the cap without compounding credentials.
    const MIN_ACTIVATION_BALANCE: Gwei;

    /// Effective balance cap with compounding credentials.
    const MAX_EFFECTIVE_BALANCE_ELECTRA: Gwei;

    /// Initial slashing penalty quotient from Electra on.
    const MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA: u64;

    /// Divides a slashed balance into the whistleblower reward from Electra on.
    const WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA: u64;

    /// Capacity of the pending deposit queue.
    const PENDING_DEPOSITS_LIMIT: u64;

    /// Capacity of the pending partial withdrawal queue.
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64;

    /// Capacity of the pending consolidation queue.
    const PENDING_CONSOLIDATIONS_LIMIT: u64;

    /// Attester slashings per block from Electra on.
    const MAX_ATTESTER_SLASHINGS_ELECTRA: u64;

    /// Attestations per block from Electra on, each now spanning many committees.
    const MAX_ATTESTATIONS_ELECTRA: u64;

    /// Deposit requests per execution payload.
    const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: u64;

    /// Withdrawal requests per execution payload.
    const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: u64;

    /// Consolidation requests per execution payload.
    const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: u64;

    /// Pending partial withdrawals served per block.
    const MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: u64;

    /// Pending deposits applied per epoch, bounding epoch processing.
    const MAX_PENDING_DEPOSITS_PER_EPOCH: u64;

    /// Depth of the commitment list's proof inside a block body.
    const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64;

    /// Field elements in a cell, the unit of PeerDAS sampling.
    const FIELD_ELEMENTS_PER_CELL: u64;

    /// Field elements in a blob after Reed-Solomon extension by a factor of two.
    const FIELD_ELEMENTS_PER_EXT_BLOB: u64;

    /// Cells in an extended blob.
    const CELLS_PER_EXT_BLOB: u64;

    /// Columns of the extended blob matrix, one cell per blob each.
    const NUMBER_OF_COLUMNS: u64;

    /// Members of a payload timeliness committee, large enough to resist a minority of withholders.
    const PTC_SIZE: u64;

    /// Payload attestations per block.
    const MAX_PAYLOAD_ATTESTATIONS: u64;

    /// Builder deposit requests per execution payload.
    const MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD: u64;

    /// Builder exit requests per execution payload.
    const MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD: u64;

    /// Builders the withdrawal sweep inspects per block, bounding its cost.
    const MAX_BUILDERS_PER_WITHDRAWALS_SWEEP: u64;

    /// Largest encoded signed aggregate accepted on the wire, now that its lists are unbounded.
    const MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE: u64;

    /// Largest encoded attester slashing accepted on the wire.
    const MAX_ATTESTER_SLASHING_SIZE: u64;

    /// Largest encoded signed payload bid accepted on the wire.
    const MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE: u64;

    /// Validators in one committee, which bounds an attestation before Electra.
    ///
    /// Equals MAX_VALIDATORS_PER_COMMITTEE.
    type MaxValidatorsPerCommittee: Length;

    /// Validators across every committee of a slot, which bounds an attestation from Electra on.
    ///
    /// Equals MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT.
    type MaxValidatorsPerSlot: Length;

    /// Committees in a slot, one bit each in an attestation.
    ///
    /// Equals MAX_COMMITTEES_PER_SLOT.
    type MaxCommitteesPerSlot: Length;

    /// Proposers in an epoch.
    ///
    /// Equals SLOTS_PER_EPOCH.
    type SlotsPerEpoch: Length;

    /// Proposers the state precomputes.
    ///
    /// Equals (MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH.
    type ProposerLookaheadSlots: Length;

    /// Recent block and state roots.
    ///
    /// Equals SLOTS_PER_HISTORICAL_ROOT.
    type SlotsPerHistoricalRoot: Length;

    /// Historical roots and summaries.
    ///
    /// Equals HISTORICAL_ROOTS_LIMIT.
    type HistoricalRootsLimit: Length;

    /// Validators and their per-validator lists.
    ///
    /// Equals VALIDATOR_REGISTRY_LIMIT.
    type ValidatorRegistryLimit: Length;

    /// Randao mixes.
    ///
    /// Equals EPOCHS_PER_HISTORICAL_VECTOR.
    type EpochsPerHistoricalVector: Length;

    /// Slashed balance accumulators.
    ///
    /// Equals EPOCHS_PER_SLASHINGS_VECTOR.
    type EpochsPerSlashingsVector: Length;

    /// Eth1 data votes in a voting period.
    ///
    /// Equals EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH.
    type Eth1DataVotesLimit: Length;

    /// Proposer slashings in a block.
    ///
    /// Equals MAX_PROPOSER_SLASHINGS.
    type MaxProposerSlashings: Length;

    /// Attester slashings in a block before Electra.
    ///
    /// Equals MAX_ATTESTER_SLASHINGS.
    type MaxAttesterSlashings: Length;

    /// Attestations in a block before Electra.
    ///
    /// Equals MAX_ATTESTATIONS.
    type MaxAttestations: Length;

    /// Attestations a phase0 state keeps per epoch.
    ///
    /// Equals MAX_ATTESTATIONS * SLOTS_PER_EPOCH.
    type MaxPendingAttestations: Length;

    /// Attester slashings in a block from Electra on.
    ///
    /// Equals MAX_ATTESTER_SLASHINGS_ELECTRA.
    type MaxAttesterSlashingsElectra: Length;

    /// Attestations in a block from Electra on.
    ///
    /// Equals MAX_ATTESTATIONS_ELECTRA.
    type MaxAttestationsElectra: Length;

    /// Deposits in a block.
    ///
    /// Equals MAX_DEPOSITS.
    type MaxDeposits: Length;

    /// Voluntary exits in a block.
    ///
    /// Equals MAX_VOLUNTARY_EXITS.
    type MaxVoluntaryExits: Length;

    /// Credential changes in a block.
    ///
    /// Equals MAX_BLS_TO_EXECUTION_CHANGES.
    type MaxBlsToExecutionChanges: Length;

    /// Members of a sync committee.
    ///
    /// Equals SYNC_COMMITTEE_SIZE.
    type SyncCommitteeSize: Length;

    /// Members of a sync subcommittee.
    ///
    /// Equals SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT.
    type SyncSubcommitteeSize: Length;

    /// Bytes of an execution transaction.
    ///
    /// Equals MAX_BYTES_PER_TRANSACTION.
    type MaxBytesPerTransaction: Length;

    /// Transactions in a payload.
    ///
    /// Equals MAX_TRANSACTIONS_PER_PAYLOAD.
    type MaxTransactionsPerPayload: Length;

    /// Bytes of the logs bloom.
    ///
    /// Equals BYTES_PER_LOGS_BLOOM.
    type BytesPerLogsBloom: Length;

    /// Bytes of extra data.
    ///
    /// Equals MAX_EXTRA_DATA_BYTES.
    type MaxExtraDataBytes: Length;

    /// Withdrawals in a payload.
    ///
    /// Equals MAX_WITHDRAWALS_PER_PAYLOAD.
    type MaxWithdrawalsPerPayload: Length;

    /// Blob commitments in a block.
    ///
    /// Equals MAX_BLOB_COMMITMENTS_PER_BLOCK.
    type MaxBlobCommitmentsPerBlock: Length;

    /// Siblings in a single commitment's inclusion proof.
    ///
    /// Equals KZG_COMMITMENT_INCLUSION_PROOF_DEPTH.
    type KzgCommitmentInclusionProofDepth: Length;

    /// Siblings in the commitment list's inclusion proof.
    ///
    /// Equals KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH.
    type KzgCommitmentsInclusionProofDepth: Length;

    /// Bytes of a blob.
    ///
    /// Equals BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB.
    type BytesPerBlob: Length;

    /// Bytes of a cell.
    ///
    /// Equals BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_CELL.
    type BytesPerCell: Length;

    /// Cells of an extended blob.
    ///
    /// Equals CELLS_PER_EXT_BLOB.
    type CellsPerExtBlob: Length;

    /// Columns of the extended blob matrix.
    ///
    /// Equals NUMBER_OF_COLUMNS.
    type NumberOfColumns: Length;

    /// Cell proofs a block's blobs can carry.
    ///
    /// Equals FIELD_ELEMENTS_PER_EXT_BLOB * MAX_BLOB_COMMITMENTS_PER_BLOCK.
    type MaxCellProofsPerBlock: Length;

    /// Pending deposits.
    ///
    /// Equals PENDING_DEPOSITS_LIMIT.
    type PendingDepositsLimit: Length;

    /// Pending partial withdrawals.
    ///
    /// Equals PENDING_PARTIAL_WITHDRAWALS_LIMIT.
    type PendingPartialWithdrawalsLimit: Length;

    /// Pending consolidations.
    ///
    /// Equals PENDING_CONSOLIDATIONS_LIMIT.
    type PendingConsolidationsLimit: Length;

    /// Deposit requests in a payload.
    ///
    /// Equals MAX_DEPOSIT_REQUESTS_PER_PAYLOAD.
    type MaxDepositRequestsPerPayload: Length;

    /// Withdrawal requests in a payload.
    ///
    /// Equals MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD.
    type MaxWithdrawalRequestsPerPayload: Length;

    /// Consolidation requests in a payload.
    ///
    /// Equals MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD.
    type MaxConsolidationRequestsPerPayload: Length;

    /// Members of a payload timeliness committee.
    ///
    /// Equals PTC_SIZE.
    type PtcSize: Length;

    /// Payload timeliness committees the state keeps: previous, current, and lookahead epochs.
    ///
    /// Equals (MIN_SEED_LOOKAHEAD + 2) * SLOTS_PER_EPOCH.
    type PtcWindowSlots: Length;

    /// Pending builder payments of the previous and current epochs.
    ///
    /// Equals 2 * SLOTS_PER_EPOCH.
    type BuilderPendingPaymentsSlots: Length;
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Length;

    use super::*;
    use crate::constants::{BYTES_PER_FIELD_ELEMENT, SYNC_COMMITTEE_SUBNET_COUNT};

    /// Every length type, with the constant expression it stands for.
    #[expect(
        clippy::too_many_lines,
        reason = "a data table with one row per length type"
    )]
    fn length_table<P: Preset>() -> Vec<(&'static str, usize, u64)> {
        vec![
            (
                "MaxValidatorsPerCommittee",
                P::MaxValidatorsPerCommittee::LEN,
                P::MAX_VALIDATORS_PER_COMMITTEE,
            ),
            (
                "MaxValidatorsPerSlot",
                P::MaxValidatorsPerSlot::LEN,
                P::MAX_VALIDATORS_PER_COMMITTEE * P::MAX_COMMITTEES_PER_SLOT,
            ),
            (
                "MaxCommitteesPerSlot",
                P::MaxCommitteesPerSlot::LEN,
                P::MAX_COMMITTEES_PER_SLOT,
            ),
            ("SlotsPerEpoch", P::SlotsPerEpoch::LEN, P::SLOTS_PER_EPOCH),
            (
                "ProposerLookaheadSlots",
                P::ProposerLookaheadSlots::LEN,
                (P::MIN_SEED_LOOKAHEAD + 1) * P::SLOTS_PER_EPOCH,
            ),
            (
                "SlotsPerHistoricalRoot",
                P::SlotsPerHistoricalRoot::LEN,
                P::SLOTS_PER_HISTORICAL_ROOT,
            ),
            (
                "HistoricalRootsLimit",
                P::HistoricalRootsLimit::LEN,
                P::HISTORICAL_ROOTS_LIMIT,
            ),
            (
                "ValidatorRegistryLimit",
                P::ValidatorRegistryLimit::LEN,
                P::VALIDATOR_REGISTRY_LIMIT,
            ),
            (
                "EpochsPerHistoricalVector",
                P::EpochsPerHistoricalVector::LEN,
                P::EPOCHS_PER_HISTORICAL_VECTOR,
            ),
            (
                "EpochsPerSlashingsVector",
                P::EpochsPerSlashingsVector::LEN,
                P::EPOCHS_PER_SLASHINGS_VECTOR,
            ),
            (
                "Eth1DataVotesLimit",
                P::Eth1DataVotesLimit::LEN,
                P::EPOCHS_PER_ETH1_VOTING_PERIOD * P::SLOTS_PER_EPOCH,
            ),
            (
                "MaxProposerSlashings",
                P::MaxProposerSlashings::LEN,
                P::MAX_PROPOSER_SLASHINGS,
            ),
            (
                "MaxAttesterSlashings",
                P::MaxAttesterSlashings::LEN,
                P::MAX_ATTESTER_SLASHINGS,
            ),
            (
                "MaxAttestations",
                P::MaxAttestations::LEN,
                P::MAX_ATTESTATIONS,
            ),
            (
                "MaxPendingAttestations",
                P::MaxPendingAttestations::LEN,
                P::MAX_ATTESTATIONS * P::SLOTS_PER_EPOCH,
            ),
            (
                "MaxAttesterSlashingsElectra",
                P::MaxAttesterSlashingsElectra::LEN,
                P::MAX_ATTESTER_SLASHINGS_ELECTRA,
            ),
            (
                "MaxAttestationsElectra",
                P::MaxAttestationsElectra::LEN,
                P::MAX_ATTESTATIONS_ELECTRA,
            ),
            ("MaxDeposits", P::MaxDeposits::LEN, P::MAX_DEPOSITS),
            (
                "MaxVoluntaryExits",
                P::MaxVoluntaryExits::LEN,
                P::MAX_VOLUNTARY_EXITS,
            ),
            (
                "MaxBlsToExecutionChanges",
                P::MaxBlsToExecutionChanges::LEN,
                P::MAX_BLS_TO_EXECUTION_CHANGES,
            ),
            (
                "SyncCommitteeSize",
                P::SyncCommitteeSize::LEN,
                P::SYNC_COMMITTEE_SIZE,
            ),
            (
                "SyncSubcommitteeSize",
                P::SyncSubcommitteeSize::LEN,
                P::SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT,
            ),
            (
                "MaxBytesPerTransaction",
                P::MaxBytesPerTransaction::LEN,
                P::MAX_BYTES_PER_TRANSACTION,
            ),
            (
                "MaxTransactionsPerPayload",
                P::MaxTransactionsPerPayload::LEN,
                P::MAX_TRANSACTIONS_PER_PAYLOAD,
            ),
            (
                "BytesPerLogsBloom",
                P::BytesPerLogsBloom::LEN,
                P::BYTES_PER_LOGS_BLOOM,
            ),
            (
                "MaxExtraDataBytes",
                P::MaxExtraDataBytes::LEN,
                P::MAX_EXTRA_DATA_BYTES,
            ),
            (
                "MaxWithdrawalsPerPayload",
                P::MaxWithdrawalsPerPayload::LEN,
                P::MAX_WITHDRAWALS_PER_PAYLOAD,
            ),
            (
                "MaxBlobCommitmentsPerBlock",
                P::MaxBlobCommitmentsPerBlock::LEN,
                P::MAX_BLOB_COMMITMENTS_PER_BLOCK,
            ),
            (
                "KzgCommitmentInclusionProofDepth",
                P::KzgCommitmentInclusionProofDepth::LEN,
                P::KZG_COMMITMENT_INCLUSION_PROOF_DEPTH,
            ),
            (
                "KzgCommitmentsInclusionProofDepth",
                P::KzgCommitmentsInclusionProofDepth::LEN,
                P::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
            ),
            (
                "BytesPerBlob",
                P::BytesPerBlob::LEN,
                BYTES_PER_FIELD_ELEMENT * P::FIELD_ELEMENTS_PER_BLOB,
            ),
            (
                "BytesPerCell",
                P::BytesPerCell::LEN,
                BYTES_PER_FIELD_ELEMENT * P::FIELD_ELEMENTS_PER_CELL,
            ),
            (
                "CellsPerExtBlob",
                P::CellsPerExtBlob::LEN,
                P::CELLS_PER_EXT_BLOB,
            ),
            (
                "NumberOfColumns",
                P::NumberOfColumns::LEN,
                P::NUMBER_OF_COLUMNS,
            ),
            (
                "MaxCellProofsPerBlock",
                P::MaxCellProofsPerBlock::LEN,
                P::FIELD_ELEMENTS_PER_EXT_BLOB * P::MAX_BLOB_COMMITMENTS_PER_BLOCK,
            ),
            (
                "PendingDepositsLimit",
                P::PendingDepositsLimit::LEN,
                P::PENDING_DEPOSITS_LIMIT,
            ),
            (
                "PendingPartialWithdrawalsLimit",
                P::PendingPartialWithdrawalsLimit::LEN,
                P::PENDING_PARTIAL_WITHDRAWALS_LIMIT,
            ),
            (
                "PendingConsolidationsLimit",
                P::PendingConsolidationsLimit::LEN,
                P::PENDING_CONSOLIDATIONS_LIMIT,
            ),
            (
                "MaxDepositRequestsPerPayload",
                P::MaxDepositRequestsPerPayload::LEN,
                P::MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
            ),
            (
                "MaxWithdrawalRequestsPerPayload",
                P::MaxWithdrawalRequestsPerPayload::LEN,
                P::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
            ),
            (
                "MaxConsolidationRequestsPerPayload",
                P::MaxConsolidationRequestsPerPayload::LEN,
                P::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
            ),
            ("PtcSize", P::PtcSize::LEN, P::PTC_SIZE),
            (
                "PtcWindowSlots",
                P::PtcWindowSlots::LEN,
                (P::MIN_SEED_LOOKAHEAD + 2) * P::SLOTS_PER_EPOCH,
            ),
            (
                "BuilderPendingPaymentsSlots",
                P::BuilderPendingPaymentsSlots::LEN,
                2 * P::SLOTS_PER_EPOCH,
            ),
        ]
    }

    /// Asserts that every length type equals its constant expression.
    fn assert_lengths_match_constants<P: Preset>() {
        for (name, length, constant) in length_table::<P>() {
            assert_eq!(
                length as u64, constant,
                "{name} disagrees with its constant"
            );
        }
    }

    #[test]
    fn mainnet_lengths_match_constants() {
        assert_lengths_match_constants::<Mainnet>();
    }

    #[test]
    fn minimal_lengths_match_constants() {
        assert_lengths_match_constants::<Minimal>();
    }
}
