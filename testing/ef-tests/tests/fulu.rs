//! The Fulu consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.
//! Each test pins every handler's case count, so a lost vector directory fails too.

use axiom_ef_tests::{
    Blocks, ChainReplay, EpochProcessing, Fork, LightClient, MerkleProofs, Networking, Operations,
    Rewards, SszStatic, StoreReplay, Suite, Transition,
    forks::{Electra, Fulu},
};
use axiom_types::{Mainnet, Minimal};

/// Every container type the static SSZ vectors of this fork cover.
const CONTAINERS: [&str; 60] = [
    "AggregateAndProof",
    "Attestation",
    "AttestationData",
    "AttesterSlashing",
    "BLSToExecutionChange",
    "BeaconBlock",
    "BeaconBlockBody",
    "BeaconBlockHeader",
    "BeaconState",
    "Checkpoint",
    "ConsolidationRequest",
    "ContributionAndProof",
    "DataColumnSidecar",
    "DataColumnsByRootIdentifier",
    "Deposit",
    "DepositData",
    "DepositMessage",
    "DepositRequest",
    "Eth1Block",
    "Eth1Data",
    "ExecutionPayload",
    "ExecutionPayloadHeader",
    "ExecutionRequests",
    "Fork",
    "ForkData",
    "HistoricalSummary",
    "IndexedAttestation",
    "LightClientBootstrap",
    "LightClientFinalityUpdate",
    "LightClientHeader",
    "LightClientOptimisticUpdate",
    "LightClientUpdate",
    "MatrixEntry",
    "NewPayloadRequest",
    "PartialDataColumnGroupID",
    "PartialDataColumnHeader",
    "PartialDataColumnPartsMetadata",
    "PartialDataColumnSidecar",
    "PendingConsolidation",
    "PendingDeposit",
    "PendingPartialWithdrawal",
    "PowBlock",
    "ProposerSlashing",
    "SignedAggregateAndProof",
    "SignedBLSToExecutionChange",
    "SignedBeaconBlock",
    "SignedBeaconBlockHeader",
    "SignedContributionAndProof",
    "SignedVoluntaryExit",
    "SigningData",
    "SingleAttestation",
    "SyncAggregate",
    "SyncAggregatorSelectionData",
    "SyncCommittee",
    "SyncCommitteeContribution",
    "SyncCommitteeMessage",
    "Validator",
    "VoluntaryExit",
    "Withdrawal",
    "WithdrawalRequest",
];

/// Fork choice cases per handler, replayed by the store and by the node's chain.
const FORK_CHOICE_MINIMAL: &[(&str, usize)] = &[
    ("deposit_with_reorg", 1),
    ("ex_ante", 3),
    ("get_head", 11),
    ("get_proposer_head", 3),
    ("on_block", 40),
    ("reorg", 8),
    ("withholding", 2),
];

/// Fork choice cases per handler on the mainnet preset.
const FORK_CHOICE_MAINNET: &[(&str, usize)] = &[
    ("ex_ante", 5),
    ("get_head", 7),
    ("get_proposer_head", 3),
    ("on_block", 23),
];

#[test]
fn ssz_static_minimal() {
    let runner = SszStatic::<Minimal, Fulu>::default();
    let expected = CONTAINERS.map(|container| (container, 123));
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn ssz_static_mainnet() {
    let runner = SszStatic::<Mainnet, Fulu>::default();
    let expected = CONTAINERS.map(|container| (container, 5));
    Suite::check(&runner, "mainnet", "fulu", &expected);
}

#[test]
fn operations_minimal() {
    let runner = Operations::<Minimal, Fulu>::default();
    let expected = [
        ("attestation", 49),
        ("attester_slashing", 30),
        ("block_header", 6),
        ("bls_to_execution_change", 14),
        ("consolidation_request", 37),
        ("deposit_request", 13),
        ("execution_payload", 39),
        ("proposer_slashing", 28),
        ("sync_aggregate", 24),
        ("voluntary_exit", 21),
        ("withdrawal_request", 29),
        ("withdrawals", 81),
    ];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn operations_mainnet() {
    let runner = Operations::<Mainnet, Fulu>::default();
    let expected = [
        ("attestation", 45),
        ("attester_slashing", 30),
        ("block_header", 6),
        ("bls_to_execution_change", 14),
        ("consolidation_request", 10),
        ("deposit_request", 13),
        ("execution_payload", 39),
        ("proposer_slashing", 28),
        ("sync_aggregate", 26),
        ("voluntary_exit", 25),
        ("withdrawal_request", 19),
        ("withdrawals", 80),
    ];
    Suite::check(&runner, "mainnet", "fulu", &expected);
}

#[test]
fn epoch_processing_minimal() {
    let runner = EpochProcessing::<Minimal, Fulu>::default();
    let expected = [
        ("effective_balance_updates", 2),
        ("eth1_data_reset", 2),
        ("historical_summaries_update", 1),
        ("inactivity_updates", 21),
        ("justification_and_finalization", 10),
        ("participation_flag_updates", 12),
        ("pending_consolidations", 13),
        ("pending_deposits", 44),
        ("proposer_lookahead", 2),
        ("randao_mixes_reset", 1),
        ("registry_updates", 23),
        ("rewards_and_penalties", 15),
        ("slashings", 5),
        ("slashings_reset", 1),
        ("sync_committee_updates", 5),
    ];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn epoch_processing_mainnet() {
    let runner = EpochProcessing::<Mainnet, Fulu>::default();
    let expected = [
        ("effective_balance_updates", 2),
        ("eth1_data_reset", 2),
        ("historical_summaries_update", 1),
        ("inactivity_updates", 21),
        ("justification_and_finalization", 10),
        ("participation_flag_updates", 10),
        ("pending_consolidations", 13),
        ("pending_deposits", 43),
        ("proposer_lookahead", 2),
        ("randao_mixes_reset", 1),
        ("registry_updates", 16),
        ("rewards_and_penalties", 15),
        ("slashings", 5),
        ("slashings_reset", 1),
    ];
    Suite::check(&runner, "mainnet", "fulu", &expected);
}

#[test]
fn sanity_minimal() {
    let runner = Blocks::<Minimal, Fulu>::sanity();
    let expected = [("blocks", 88), ("slots", 15)];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn sanity_mainnet() {
    let runner = Blocks::<Mainnet, Fulu>::sanity();
    let expected = [("blocks", 76), ("slots", 15)];
    Suite::check(&runner, "mainnet", "fulu", &expected);
}

#[test]
fn finality_minimal() {
    let runner = Blocks::<Minimal, Fulu>::finality();
    let expected = [("finality", 5)];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn finality_mainnet() {
    let runner = Blocks::<Mainnet, Fulu>::finality();
    let expected = [("finality", 5)];
    Suite::check(&runner, "mainnet", "fulu", &expected);
}

#[test]
fn random_minimal() {
    let runner = Blocks::<Minimal, Fulu>::random();
    let expected = [("random", 16)];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn random_mainnet() {
    let runner = Blocks::<Mainnet, Fulu>::random();
    let expected = [("random", 16)];
    Suite::check(&runner, "mainnet", "fulu", &expected);
}

#[test]
fn rewards_minimal() {
    let runner = Rewards::<Minimal, Fulu>::default();
    let expected = [
        ("basic", 11),
        ("inactivity_scores", 12),
        ("leak", 13),
        ("random", 10),
    ];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn rewards_mainnet() {
    let runner = Rewards::<Mainnet, Fulu>::default();
    let expected = [
        ("basic", 11),
        ("inactivity_scores", 12),
        ("leak", 13),
        ("random", 10),
    ];
    Suite::check(&runner, "mainnet", "fulu", &expected);
}

#[test]
fn fork_minimal() {
    let runner = Fork::<Minimal, Fulu>::default();
    let expected = [("fork", 20)];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn fork_mainnet() {
    let runner = Fork::<Mainnet, Fulu>::default();
    let expected = [("fork", 18)];
    Suite::check(&runner, "mainnet", "fulu", &expected);
}

#[test]
fn transition_minimal() {
    let runner = Transition::<Minimal, Electra, Fulu>::default();
    let expected = [("core", 31)];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn transition_mainnet() {
    let runner = Transition::<Mainnet, Electra, Fulu>::default();
    let expected = [("core", 25)];
    Suite::check(&runner, "mainnet", "fulu", &expected);
}

#[test]
fn fork_choice_minimal() {
    let runner = StoreReplay::<Minimal, Fulu>::fork_choice();
    Suite::check(&runner, "minimal", "fulu", FORK_CHOICE_MINIMAL);
}

#[test]
fn chain_replay_minimal() {
    let runner = ChainReplay::<Minimal, Fulu>::new();
    Suite::check(&runner, "minimal", "fulu", FORK_CHOICE_MINIMAL);
}

#[test]
fn fork_choice_mainnet() {
    let runner = StoreReplay::<Mainnet, Fulu>::fork_choice();
    Suite::check(&runner, "mainnet", "fulu", FORK_CHOICE_MAINNET);
}

#[test]
fn chain_replay_mainnet() {
    let runner = ChainReplay::<Mainnet, Fulu>::new();
    Suite::check(&runner, "mainnet", "fulu", FORK_CHOICE_MAINNET);
}

#[test]
fn networking_minimal() {
    let runner = Networking::<Minimal, Fulu>::default();
    let expected = [
        ("compute_columns_for_custody_group", 5),
        ("get_custody_groups", 11),
        ("gossip_attester_slashing", 12),
        ("gossip_beacon_aggregate_and_proof", 33),
        ("gossip_beacon_attestation", 23),
        ("gossip_beacon_block", 23),
        ("gossip_bls_to_execution_change", 6),
        ("gossip_data_column_sidecar", 17),
        ("gossip_partial_data_column_sidecar", 24),
        ("gossip_proposer_slashing", 9),
        ("gossip_sync_committee_contribution_and_proof", 14),
        ("gossip_sync_committee_message", 7),
        ("gossip_voluntary_exit", 14),
    ];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn networking_mainnet() {
    let runner = Networking::<Mainnet, Fulu>::default();
    let expected = [
        ("compute_columns_for_custody_group", 5),
        ("get_custody_groups", 11),
        ("gossip_attester_slashing", 12),
        ("gossip_beacon_aggregate_and_proof", 33),
        ("gossip_beacon_attestation", 23),
        ("gossip_beacon_block", 23),
        ("gossip_bls_to_execution_change", 6),
        ("gossip_data_column_sidecar", 17),
        ("gossip_partial_data_column_sidecar", 24),
        ("gossip_proposer_slashing", 9),
        ("gossip_sync_committee_contribution_and_proof", 15),
        ("gossip_sync_committee_message", 7),
        ("gossip_voluntary_exit", 14),
    ];
    Suite::check(&runner, "mainnet", "fulu", &expected);
}

#[test]
fn merkle_proof_minimal() {
    let runner = MerkleProofs::<Minimal, Fulu>::merkle_proof();
    let expected = [("single_merkle_proof", 4)];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn merkle_proof_mainnet() {
    let runner = MerkleProofs::<Mainnet, Fulu>::merkle_proof();
    let expected = [("single_merkle_proof", 4)];
    Suite::check(&runner, "mainnet", "fulu", &expected);
}

#[test]
fn light_client_minimal() {
    let runner = LightClient::<Minimal, Fulu>::default();
    let expected = [
        ("data_collection", 1),
        ("single_merkle_proof", 4),
        ("sync", 6),
        ("update_ranking", 1),
    ];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn light_client_mainnet() {
    let runner = LightClient::<Mainnet, Fulu>::default();
    let expected = [("single_merkle_proof", 4)];
    Suite::check(&runner, "mainnet", "fulu", &expected);
}

#[test]
fn fast_confirmation_minimal() {
    let runner = StoreReplay::<Minimal, Fulu>::fast_confirmation();
    let expected = [
        ("basic", 3),
        ("current_epoch", 22),
        ("empty_slots", 5),
        ("ffg", 2),
        ("is_one_confirmed", 19),
        ("previous_epoch", 108),
        ("reconfirmation", 3),
        ("restart_gu", 6),
        ("revert_finality", 8),
        ("variables", 8),
    ];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn sync_minimal() {
    let runner = StoreReplay::<Minimal, Fulu>::sync();
    let expected = [("optimistic", 1)];
    Suite::check(&runner, "minimal", "fulu", &expected);
}

#[test]
fn sync_mainnet() {
    let runner = StoreReplay::<Mainnet, Fulu>::sync();
    let expected = [("optimistic", 1)];
    Suite::check(&runner, "mainnet", "fulu", &expected);
}
