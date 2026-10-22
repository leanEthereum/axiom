//! The phase0 consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.
//! Each test pins every handler's case count, so a lost vector directory fails too.
//! The fork choice and networking vectors run in their own suites.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Genesis, Networking, Operations, PendingAttestationRewards, Shuffling,
    SszStatic, Suite, forks::Phase0,
};
use axiom_types::{Mainnet, Minimal};

/// Every container type the static SSZ vectors of this fork cover.
const CONTAINERS: [&str; 27] = [
    "AggregateAndProof",
    "Attestation",
    "AttestationData",
    "AttesterSlashing",
    "BeaconBlock",
    "BeaconBlockBody",
    "BeaconBlockHeader",
    "BeaconState",
    "Checkpoint",
    "Deposit",
    "DepositData",
    "DepositMessage",
    "Eth1Block",
    "Eth1Data",
    "Fork",
    "ForkData",
    "HistoricalBatch",
    "IndexedAttestation",
    "PendingAttestation",
    "ProposerSlashing",
    "SignedAggregateAndProof",
    "SignedBeaconBlock",
    "SignedBeaconBlockHeader",
    "SignedVoluntaryExit",
    "SigningData",
    "Validator",
    "VoluntaryExit",
];

#[test]
fn ssz_static_minimal() {
    let runner = SszStatic::<Minimal, Phase0>::default();
    let expected = CONTAINERS.map(|container| (container, 123));
    Suite::check(&runner, "minimal", "phase0", &expected);
}

#[test]
fn ssz_static_mainnet() {
    let runner = SszStatic::<Mainnet, Phase0>::default();
    let expected = CONTAINERS.map(|container| (container, 5));
    Suite::check(&runner, "mainnet", "phase0", &expected);
}

#[test]
fn operations_minimal() {
    let runner = Operations::<Minimal, Phase0>::default();
    let expected = [
        ("attestation", 41),
        ("attester_slashing", 30),
        ("block_header", 6),
        ("deposit", 19),
        ("proposer_slashing", 28),
        ("voluntary_exit", 10),
    ];
    Suite::check(&runner, "minimal", "phase0", &expected);
}

#[test]
fn operations_mainnet() {
    let runner = Operations::<Mainnet, Phase0>::default();
    let expected = [
        ("attestation", 41),
        ("attester_slashing", 30),
        ("block_header", 6),
        ("deposit", 19),
        ("proposer_slashing", 28),
        ("voluntary_exit", 9),
    ];
    Suite::check(&runner, "mainnet", "phase0", &expected);
}

#[test]
fn epoch_processing_minimal() {
    let runner = EpochProcessing::<Minimal, Phase0>::default();
    let expected = [
        ("effective_balance_updates", 1),
        ("eth1_data_reset", 2),
        ("historical_roots_update", 1),
        ("justification_and_finalization", 10),
        ("participation_record_updates", 1),
        ("randao_mixes_reset", 1),
        ("registry_updates", 15),
        ("rewards_and_penalties", 19),
        ("slashings", 5),
        ("slashings_reset", 1),
    ];
    Suite::check(&runner, "minimal", "phase0", &expected);
}

#[test]
fn epoch_processing_mainnet() {
    let runner = EpochProcessing::<Mainnet, Phase0>::default();
    let expected = [
        ("effective_balance_updates", 1),
        ("eth1_data_reset", 2),
        ("historical_roots_update", 1),
        ("justification_and_finalization", 10),
        ("participation_record_updates", 1),
        ("randao_mixes_reset", 1),
        ("registry_updates", 11),
        ("rewards_and_penalties", 19),
        ("slashings", 5),
        ("slashings_reset", 1),
    ];
    Suite::check(&runner, "mainnet", "phase0", &expected);
}

#[test]
fn sanity_minimal() {
    let runner = Blocks::<Minimal, Phase0>::sanity();
    let expected = [("blocks", 47), ("slots", 7)];
    Suite::check(&runner, "minimal", "phase0", &expected);
}

#[test]
fn sanity_mainnet() {
    let runner = Blocks::<Mainnet, Phase0>::sanity();
    let expected = [("blocks", 42), ("slots", 7)];
    Suite::check(&runner, "mainnet", "phase0", &expected);
}

#[test]
fn finality_minimal() {
    let runner = Blocks::<Minimal, Phase0>::finality();
    let expected = [("finality", 5)];
    Suite::check(&runner, "minimal", "phase0", &expected);
}

#[test]
fn finality_mainnet() {
    let runner = Blocks::<Mainnet, Phase0>::finality();
    let expected = [("finality", 5)];
    Suite::check(&runner, "mainnet", "phase0", &expected);
}

#[test]
fn random_minimal() {
    let runner = Blocks::<Minimal, Phase0>::random();
    let expected = [("random", 16)];
    Suite::check(&runner, "minimal", "phase0", &expected);
}

#[test]
fn random_mainnet() {
    let runner = Blocks::<Mainnet, Phase0>::random();
    let expected = [("random", 16)];
    Suite::check(&runner, "mainnet", "phase0", &expected);
}

#[test]
fn rewards_minimal() {
    let runner = PendingAttestationRewards::<Minimal>::default();
    let expected = [("basic", 21), ("leak", 18), ("random", 10)];
    Suite::check(&runner, "minimal", "phase0", &expected);
}

#[test]
fn rewards_mainnet() {
    let runner = PendingAttestationRewards::<Mainnet>::default();
    let expected = [("basic", 21), ("leak", 18), ("random", 10)];
    Suite::check(&runner, "mainnet", "phase0", &expected);
}

#[test]
fn shuffling_minimal() {
    let runner = Shuffling::<Minimal>::default();
    let expected = [("core", 300)];
    Suite::check(&runner, "minimal", "phase0", &expected);
}

#[test]
fn shuffling_mainnet() {
    let runner = Shuffling::<Mainnet>::default();
    let expected = [("core", 300)];
    Suite::check(&runner, "mainnet", "phase0", &expected);
}

#[test]
fn genesis_minimal() {
    // Only the minimal preset ships genesis vectors.
    let runner = Genesis::<Minimal>::default();
    let expected = [("initialization", 5), ("validity", 5)];
    Suite::check(&runner, "minimal", "phase0", &expected);
}

#[test]
fn networking_minimal() {
    let runner = Networking::<Minimal, Phase0>::default();
    let expected = [
        ("gossip_attester_slashing", 12),
        ("gossip_beacon_aggregate_and_proof", 20),
        ("gossip_beacon_attestation", 16),
        ("gossip_beacon_block", 12),
        ("gossip_proposer_slashing", 9),
        ("gossip_voluntary_exit", 12),
    ];
    Suite::check(&runner, "minimal", "phase0", &expected);
}

#[test]
fn networking_mainnet() {
    let runner = Networking::<Mainnet, Phase0>::default();
    let expected = [
        ("gossip_attester_slashing", 12),
        ("gossip_beacon_aggregate_and_proof", 21),
        ("gossip_beacon_attestation", 16),
        ("gossip_beacon_block", 12),
        ("gossip_proposer_slashing", 9),
        ("gossip_voluntary_exit", 12),
    ];
    Suite::check(&runner, "mainnet", "phase0", &expected);
}
