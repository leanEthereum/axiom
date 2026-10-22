//! The Fulu consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use axiom_ef_tests::{
    Blocks, ChainReplay, EpochProcessing, Fork, LightClient, MerkleProofs, Networking, Operations,
    Rewards, Shuffling, SszStatic, StoreReplay, Suite, Transition,
    forks::{Electra, Fulu},
};
use axiom_types::{Mainnet, Minimal};

#[test]
fn ssz_static_minimal() {
    Suite::run(&SszStatic::<Minimal, Fulu>::default(), "minimal", "fulu");
}

#[test]
fn ssz_static_mainnet() {
    Suite::run(&SszStatic::<Mainnet, Fulu>::default(), "mainnet", "fulu");
}

#[test]
fn operations_minimal() {
    Suite::run(&Operations::<Minimal, Fulu>::default(), "minimal", "fulu");
}

#[test]
fn operations_mainnet() {
    Suite::run(&Operations::<Mainnet, Fulu>::default(), "mainnet", "fulu");
}

#[test]
fn epoch_processing_minimal() {
    Suite::run(
        &EpochProcessing::<Minimal, Fulu>::default(),
        "minimal",
        "fulu",
    );
}

#[test]
fn epoch_processing_mainnet() {
    Suite::run(
        &EpochProcessing::<Mainnet, Fulu>::default(),
        "mainnet",
        "fulu",
    );
}

#[test]
fn sanity_minimal() {
    Suite::run(&Blocks::<Minimal, Fulu>::sanity(), "minimal", "fulu");
}

#[test]
fn sanity_mainnet() {
    Suite::run(&Blocks::<Mainnet, Fulu>::sanity(), "mainnet", "fulu");
}

#[test]
fn finality_minimal() {
    Suite::run(&Blocks::<Minimal, Fulu>::finality(), "minimal", "fulu");
}

#[test]
fn finality_mainnet() {
    Suite::run(&Blocks::<Mainnet, Fulu>::finality(), "mainnet", "fulu");
}

#[test]
fn random_minimal() {
    Suite::run(&Blocks::<Minimal, Fulu>::random(), "minimal", "fulu");
}

#[test]
fn random_mainnet() {
    Suite::run(&Blocks::<Mainnet, Fulu>::random(), "mainnet", "fulu");
}

#[test]
fn rewards_minimal() {
    Suite::run(&Rewards::<Minimal, Fulu>::default(), "minimal", "fulu");
}

#[test]
fn rewards_mainnet() {
    Suite::run(&Rewards::<Mainnet, Fulu>::default(), "mainnet", "fulu");
}

#[test]
fn fork_minimal() {
    Suite::run(&Fork::<Minimal, Fulu>::default(), "minimal", "fulu");
}

#[test]
fn fork_mainnet() {
    Suite::run(&Fork::<Mainnet, Fulu>::default(), "mainnet", "fulu");
}

#[test]
fn transition_minimal() {
    Suite::run(
        &Transition::<Minimal, Electra, Fulu>::default(),
        "minimal",
        "fulu",
    );
}

#[test]
fn transition_mainnet() {
    Suite::run(
        &Transition::<Mainnet, Electra, Fulu>::default(),
        "mainnet",
        "fulu",
    );
}

#[test]
fn shuffling_minimal() {
    // Shuffling vectors exist only under phase0, and the shuffle never changed since.
    Suite::run(&Shuffling::<Minimal>::default(), "minimal", "phase0");
}

#[test]
fn shuffling_mainnet() {
    Suite::run(&Shuffling::<Mainnet>::default(), "mainnet", "phase0");
}

#[test]
fn fork_choice_minimal() {
    let runner = StoreReplay::<Minimal, Fulu>::fork_choice();
    if let Some(report) = Suite::run(&runner, "minimal", "fulu") {
        // Cases: deposit with reorg 1, ex ante 3, get head 11, proposer head 3, on block 40, reorg 8, withholding 2.
        assert_eq!((report.passed, report.skipped.len()), (68, 0));
    }
}

#[test]
fn fork_choice_mainnet() {
    let runner = StoreReplay::<Mainnet, Fulu>::fork_choice();
    if let Some(report) = Suite::run(&runner, "mainnet", "fulu") {
        // Cases: ex ante 5, get head 7, proposer head 3, on block 23.
        assert_eq!((report.passed, report.skipped.len()), (38, 0));
    }
}

#[test]
fn chain_replay_minimal() {
    let runner = ChainReplay::<Minimal, Fulu>::new();
    if let Some(report) = Suite::run(&runner, "minimal", "fulu") {
        // Cases: the fork choice cases, through the node: deposit with reorg 1, ex ante 3, get head 11, proposer head 3, on block 40, reorg 8, withholding 2.
        assert_eq!((report.passed, report.skipped.len()), (68, 0));
    }
}

#[test]
fn chain_replay_mainnet() {
    let runner = ChainReplay::<Mainnet, Fulu>::new();
    if let Some(report) = Suite::run(&runner, "mainnet", "fulu") {
        // Cases: the fork choice cases, through the node: ex ante 5, get head 7, proposer head 3, on block 23.
        assert_eq!((report.passed, report.skipped.len()), (38, 0));
    }
}

#[test]
fn networking_minimal() {
    Suite::run(&Networking::<Minimal, Fulu>::default(), "minimal", "fulu");
}

#[test]
fn networking_mainnet() {
    Suite::run(&Networking::<Mainnet, Fulu>::default(), "mainnet", "fulu");
}

#[test]
fn merkle_proof_minimal() {
    let runner = MerkleProofs::<Minimal, Fulu>::merkle_proof();
    if let Some(report) = Suite::run(&runner, "minimal", "fulu") {
        // Cases: four blob commitment proofs into the block body.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}

#[test]
fn merkle_proof_mainnet() {
    let runner = MerkleProofs::<Mainnet, Fulu>::merkle_proof();
    if let Some(report) = Suite::run(&runner, "mainnet", "fulu") {
        // Cases: four blob commitment proofs into the block body.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}

#[test]
fn light_client_minimal() {
    let runner = LightClient::<Minimal, Fulu>::default();
    if let Some(report) = Suite::run(&runner, "minimal", "fulu") {
        // Cases: sync 6, update ranking 1, merkle proofs 4, data collection 1.
        assert_eq!((report.passed, report.skipped.len()), (12, 0));
    }
}

#[test]
fn light_client_mainnet() {
    let runner = LightClient::<Mainnet, Fulu>::default();
    if let Some(report) = Suite::run(&runner, "mainnet", "fulu") {
        // Cases: merkle proofs 4.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}

#[test]
fn fast_confirmation_minimal() {
    let runner = StoreReplay::<Minimal, Fulu>::fast_confirmation();
    if let Some(report) = Suite::run(&runner, "minimal", "fulu") {
        // Cases: basic 3, current epoch 22, empty slots 5, ffg 2, is one confirmed 19, previous epoch 108, reconfirmation 3, restart 6, revert finality 8, variables 8.
        assert_eq!((report.passed, report.skipped.len()), (184, 0));
    }
}

#[test]
fn sync_minimal() {
    let runner = StoreReplay::<Minimal, Fulu>::sync();
    if let Some(report) = Suite::run(&runner, "minimal", "fulu") {
        // Cases: optimistic 1.
        assert_eq!((report.passed, report.skipped.len()), (1, 0));
    }
}

#[test]
fn sync_mainnet() {
    let runner = StoreReplay::<Mainnet, Fulu>::sync();
    if let Some(report) = Suite::run(&runner, "mainnet", "fulu") {
        // Cases: optimistic 1.
        assert_eq!((report.passed, report.skipped.len()), (1, 0));
    }
}
