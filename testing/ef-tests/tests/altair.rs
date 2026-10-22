//! The Altair consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.
//! Each test pins every handler's case count, so a lost vector directory fails too.

use axiom_ef_tests::{
    Blocks, ChainReplay, EpochProcessing, Fork, LightClient, Networking, Operations, Rewards,
    SszStatic, StoreReplay, Suite, Transition,
    forks::{Altair, Phase0},
};
use axiom_types::{Mainnet, Minimal};

/// Every container type the static SSZ vectors of this fork cover.
const CONTAINERS: [&str; 38] = [
    "AggregateAndProof",
    "Attestation",
    "AttestationData",
    "AttesterSlashing",
    "BeaconBlock",
    "BeaconBlockBody",
    "BeaconBlockHeader",
    "BeaconState",
    "Checkpoint",
    "ContributionAndProof",
    "Deposit",
    "DepositData",
    "DepositMessage",
    "Eth1Block",
    "Eth1Data",
    "Fork",
    "ForkData",
    "HistoricalBatch",
    "IndexedAttestation",
    "LightClientBootstrap",
    "LightClientFinalityUpdate",
    "LightClientHeader",
    "LightClientOptimisticUpdate",
    "LightClientUpdate",
    "ProposerSlashing",
    "SignedAggregateAndProof",
    "SignedBeaconBlock",
    "SignedBeaconBlockHeader",
    "SignedContributionAndProof",
    "SignedVoluntaryExit",
    "SigningData",
    "SyncAggregate",
    "SyncAggregatorSelectionData",
    "SyncCommittee",
    "SyncCommitteeContribution",
    "SyncCommitteeMessage",
    "Validator",
    "VoluntaryExit",
];

/// Fork choice cases per handler, replayed by the store and by the node's chain.
const FORK_CHOICE_MINIMAL: &[(&str, usize)] = &[
    ("ex_ante", 3),
    ("get_head", 11),
    ("get_proposer_head", 3),
    ("on_block", 23),
    ("reorg", 8),
    ("withholding", 2),
];

/// Fork choice cases per handler on the mainnet preset.
const FORK_CHOICE_MAINNET: &[(&str, usize)] = &[
    ("ex_ante", 5),
    ("get_head", 7),
    ("get_proposer_head", 3),
    ("on_block", 6),
];

#[test]
fn ssz_static_minimal() {
    let runner = SszStatic::<Minimal, Altair>::default();
    let expected = CONTAINERS.map(|container| (container, 123));
    Suite::check(&runner, "minimal", "altair", &expected);
}

#[test]
fn ssz_static_mainnet() {
    let runner = SszStatic::<Mainnet, Altair>::default();
    let expected = CONTAINERS.map(|container| (container, 5));
    Suite::check(&runner, "mainnet", "altair", &expected);
}

#[test]
fn operations_minimal() {
    let runner = Operations::<Minimal, Altair>::default();
    let expected = [
        ("attestation", 41),
        ("attester_slashing", 30),
        ("block_header", 6),
        ("deposit", 21),
        ("proposer_slashing", 28),
        ("sync_aggregate", 24),
        ("voluntary_exit", 10),
    ];
    Suite::check(&runner, "minimal", "altair", &expected);
}

#[test]
fn operations_mainnet() {
    let runner = Operations::<Mainnet, Altair>::default();
    let expected = [
        ("attestation", 41),
        ("attester_slashing", 30),
        ("block_header", 6),
        ("deposit", 21),
        ("proposer_slashing", 28),
        ("sync_aggregate", 26),
        ("voluntary_exit", 9),
    ];
    Suite::check(&runner, "mainnet", "altair", &expected);
}

#[test]
fn epoch_processing_minimal() {
    let runner = EpochProcessing::<Minimal, Altair>::default();
    let expected = [
        ("effective_balance_updates", 1),
        ("eth1_data_reset", 2),
        ("historical_roots_update", 1),
        ("inactivity_updates", 21),
        ("justification_and_finalization", 10),
        ("participation_flag_updates", 12),
        ("randao_mixes_reset", 1),
        ("registry_updates", 15),
        ("rewards_and_penalties", 15),
        ("slashings", 5),
        ("slashings_reset", 1),
        ("sync_committee_updates", 5),
    ];
    Suite::check(&runner, "minimal", "altair", &expected);
}

#[test]
fn epoch_processing_mainnet() {
    let runner = EpochProcessing::<Mainnet, Altair>::default();
    let expected = [
        ("effective_balance_updates", 1),
        ("eth1_data_reset", 2),
        ("historical_roots_update", 1),
        ("inactivity_updates", 21),
        ("justification_and_finalization", 10),
        ("participation_flag_updates", 10),
        ("randao_mixes_reset", 1),
        ("registry_updates", 11),
        ("rewards_and_penalties", 15),
        ("slashings", 5),
        ("slashings_reset", 1),
    ];
    Suite::check(&runner, "mainnet", "altair", &expected);
}

#[test]
fn sanity_minimal() {
    let runner = Blocks::<Minimal, Altair>::sanity();
    let expected = [("blocks", 54), ("slots", 7)];
    Suite::check(&runner, "minimal", "altair", &expected);
}

#[test]
fn sanity_mainnet() {
    let runner = Blocks::<Mainnet, Altair>::sanity();
    let expected = [("blocks", 49), ("slots", 7)];
    Suite::check(&runner, "mainnet", "altair", &expected);
}

#[test]
fn finality_minimal() {
    let runner = Blocks::<Minimal, Altair>::finality();
    let expected = [("finality", 5)];
    Suite::check(&runner, "minimal", "altair", &expected);
}

#[test]
fn finality_mainnet() {
    let runner = Blocks::<Mainnet, Altair>::finality();
    let expected = [("finality", 5)];
    Suite::check(&runner, "mainnet", "altair", &expected);
}

#[test]
fn random_minimal() {
    let runner = Blocks::<Minimal, Altair>::random();
    let expected = [("random", 16)];
    Suite::check(&runner, "minimal", "altair", &expected);
}

#[test]
fn random_mainnet() {
    let runner = Blocks::<Mainnet, Altair>::random();
    let expected = [("random", 16)];
    Suite::check(&runner, "mainnet", "altair", &expected);
}

#[test]
fn rewards_minimal() {
    let runner = Rewards::<Minimal, Altair>::default();
    let expected = [
        ("basic", 11),
        ("inactivity_scores", 12),
        ("leak", 13),
        ("random", 10),
    ];
    Suite::check(&runner, "minimal", "altair", &expected);
}

#[test]
fn rewards_mainnet() {
    let runner = Rewards::<Mainnet, Altair>::default();
    let expected = [
        ("basic", 11),
        ("inactivity_scores", 12),
        ("leak", 13),
        ("random", 10),
    ];
    Suite::check(&runner, "mainnet", "altair", &expected);
}

#[test]
fn fork_minimal() {
    let runner = Fork::<Minimal, Altair>::default();
    let expected = [("fork", 19)];
    Suite::check(&runner, "minimal", "altair", &expected);
}

#[test]
fn fork_mainnet() {
    let runner = Fork::<Mainnet, Altair>::default();
    let expected = [("fork", 17)];
    Suite::check(&runner, "mainnet", "altair", &expected);
}

#[test]
fn transition_minimal() {
    let runner = Transition::<Minimal, Phase0, Altair>::default();
    let expected = [("core", 26)];
    Suite::check(&runner, "minimal", "altair", &expected);
}

#[test]
fn transition_mainnet() {
    let runner = Transition::<Mainnet, Phase0, Altair>::default();
    let expected = [("core", 22)];
    Suite::check(&runner, "mainnet", "altair", &expected);
}

#[test]
fn networking_minimal() {
    let runner = Networking::<Minimal, Altair>::default();
    let expected = [
        ("gossip_attester_slashing", 12),
        ("gossip_beacon_aggregate_and_proof", 20),
        ("gossip_beacon_attestation", 16),
        ("gossip_beacon_block", 12),
        ("gossip_proposer_slashing", 9),
        ("gossip_sync_committee_contribution_and_proof", 14),
        ("gossip_sync_committee_message", 7),
        ("gossip_voluntary_exit", 12),
    ];
    Suite::check(&runner, "minimal", "altair", &expected);
}

#[test]
fn networking_mainnet() {
    let runner = Networking::<Mainnet, Altair>::default();
    let expected = [
        ("gossip_attester_slashing", 12),
        ("gossip_beacon_aggregate_and_proof", 21),
        ("gossip_beacon_attestation", 16),
        ("gossip_beacon_block", 12),
        ("gossip_proposer_slashing", 9),
        ("gossip_sync_committee_contribution_and_proof", 15),
        ("gossip_sync_committee_message", 7),
        ("gossip_voluntary_exit", 12),
    ];
    Suite::check(&runner, "mainnet", "altair", &expected);
}

#[test]
fn light_client_minimal() {
    let runner = LightClient::<Minimal, Altair>::default();
    let expected = [
        ("data_collection", 1),
        ("single_merkle_proof", 3),
        ("sync", 8),
        ("update_ranking", 1),
    ];
    Suite::check(&runner, "minimal", "altair", &expected);
}

#[test]
fn light_client_mainnet() {
    let runner = LightClient::<Mainnet, Altair>::default();
    let expected = [("single_merkle_proof", 3)];
    Suite::check(&runner, "mainnet", "altair", &expected);
}

#[test]
fn fork_choice_minimal() {
    let runner = StoreReplay::<Minimal, Altair>::fork_choice();
    Suite::check(&runner, "minimal", "altair", FORK_CHOICE_MINIMAL);
}

#[test]
fn chain_replay_minimal() {
    let runner = ChainReplay::<Minimal, Altair>::new();
    Suite::check(&runner, "minimal", "altair", FORK_CHOICE_MINIMAL);
}

#[test]
fn fork_choice_mainnet() {
    let runner = StoreReplay::<Mainnet, Altair>::fork_choice();
    Suite::check(&runner, "mainnet", "altair", FORK_CHOICE_MAINNET);
}

#[test]
fn chain_replay_mainnet() {
    let runner = ChainReplay::<Mainnet, Altair>::new();
    Suite::check(&runner, "mainnet", "altair", FORK_CHOICE_MAINNET);
}

#[test]
fn fast_confirmation_minimal() {
    let runner = StoreReplay::<Minimal, Altair>::fast_confirmation();
    let expected = [
        ("basic", 3),
        ("current_epoch", 22),
        ("empty_slots", 5),
        ("ffg", 2),
        ("is_one_confirmed", 10),
        ("previous_epoch", 108),
        ("reconfirmation", 3),
        ("restart_gu", 6),
        ("revert_finality", 8),
        ("variables", 8),
    ];
    Suite::check(&runner, "minimal", "altair", &expected);
}
