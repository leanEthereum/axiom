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
            P::MAX_ATTESTER_SLASHINGS_ELECTRA,
        ),
        (
            "MaxAttestations",
            P::MaxAttestations::LEN,
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
