//! The Electra consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Fork, LightClient, MerkleProofs, Networking, Operations, Rewards,
    SszStatic, StoreReplay, Suite, Transition,
    forks::{Deneb, Electra},
};
use axiom_types::{Mainnet, Minimal};

#[test]
fn ssz_static_minimal() {
    Suite::run(
        &SszStatic::<Minimal, Electra>::default(),
        "minimal",
        "electra",
    );
}

#[test]
fn ssz_static_mainnet() {
    Suite::run(
        &SszStatic::<Mainnet, Electra>::default(),
        "mainnet",
        "electra",
    );
}

#[test]
fn operations_minimal() {
    Suite::run(
        &Operations::<Minimal, Electra>::default(),
        "minimal",
        "electra",
    );
}

#[test]
fn operations_mainnet() {
    Suite::run(
        &Operations::<Mainnet, Electra>::default(),
        "mainnet",
        "electra",
    );
}

#[test]
fn epoch_processing_minimal() {
    Suite::run(
        &EpochProcessing::<Minimal, Electra>::default(),
        "minimal",
        "electra",
    );
}

#[test]
fn epoch_processing_mainnet() {
    Suite::run(
        &EpochProcessing::<Mainnet, Electra>::default(),
        "mainnet",
        "electra",
    );
}

#[test]
fn sanity_minimal() {
    Suite::run(&Blocks::<Minimal, Electra>::sanity(), "minimal", "electra");
}

#[test]
fn sanity_mainnet() {
    Suite::run(&Blocks::<Mainnet, Electra>::sanity(), "mainnet", "electra");
}

#[test]
fn finality_minimal() {
    Suite::run(
        &Blocks::<Minimal, Electra>::finality(),
        "minimal",
        "electra",
    );
}

#[test]
fn finality_mainnet() {
    Suite::run(
        &Blocks::<Mainnet, Electra>::finality(),
        "mainnet",
        "electra",
    );
}

#[test]
fn random_minimal() {
    Suite::run(&Blocks::<Minimal, Electra>::random(), "minimal", "electra");
}

#[test]
fn random_mainnet() {
    Suite::run(&Blocks::<Mainnet, Electra>::random(), "mainnet", "electra");
}

#[test]
fn rewards_minimal() {
    Suite::run(
        &Rewards::<Minimal, Electra>::default(),
        "minimal",
        "electra",
    );
}

#[test]
fn rewards_mainnet() {
    Suite::run(
        &Rewards::<Mainnet, Electra>::default(),
        "mainnet",
        "electra",
    );
}

#[test]
fn fork_minimal() {
    Suite::run(&Fork::<Minimal, Electra>::default(), "minimal", "electra");
}

#[test]
fn fork_mainnet() {
    Suite::run(&Fork::<Mainnet, Electra>::default(), "mainnet", "electra");
}

#[test]
fn transition_minimal() {
    Suite::run(
        &Transition::<Minimal, Deneb, Electra>::default(),
        "minimal",
        "electra",
    );
}

#[test]
fn transition_mainnet() {
    Suite::run(
        &Transition::<Mainnet, Deneb, Electra>::default(),
        "mainnet",
        "electra",
    );
}

#[test]
fn networking_minimal() {
    Suite::run(
        &Networking::<Minimal, Electra>::default(),
        "minimal",
        "electra",
    );
}

#[test]
fn networking_mainnet() {
    Suite::run(
        &Networking::<Mainnet, Electra>::default(),
        "mainnet",
        "electra",
    );
}

#[test]
fn light_client_minimal() {
    let runner = LightClient::<Minimal, Electra>::default();
    if let Some(report) = Suite::run(&runner, "minimal", "electra") {
        // Cases: sync 5, update ranking 1, merkle proofs 4, data collection 1.
        assert_eq!((report.passed, report.skipped.len()), (11, 0));
    }
}

#[test]
fn light_client_mainnet() {
    let runner = LightClient::<Mainnet, Electra>::default();
    if let Some(report) = Suite::run(&runner, "mainnet", "electra") {
        // Cases: merkle proofs 4.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}

#[test]
fn merkle_proof_minimal() {
    let runner = MerkleProofs::<Minimal, Electra>::merkle_proof();
    if let Some(report) = Suite::run(&runner, "minimal", "electra") {
        // Cases: four blob commitment proofs into the block body.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}

#[test]
fn merkle_proof_mainnet() {
    let runner = MerkleProofs::<Mainnet, Electra>::merkle_proof();
    if let Some(report) = Suite::run(&runner, "mainnet", "electra") {
        // Cases: four blob commitment proofs into the block body.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}

#[test]
fn fork_choice_minimal() {
    let runner = StoreReplay::<Minimal, Electra>::fork_choice();
    if let Some(report) = Suite::run(&runner, "minimal", "electra") {
        // Cases: deposit with reorg 1, ex ante 3, get head 11, proposer head 3, on block 28, reorg 8, withholding 2.
        assert_eq!((report.passed, report.skipped.len()), (56, 0));
    }
}

#[test]
fn fork_choice_mainnet() {
    let runner = StoreReplay::<Mainnet, Electra>::fork_choice();
    if let Some(report) = Suite::run(&runner, "mainnet", "electra") {
        // Cases: ex ante 5, get head 7, proposer head 3, on block 11.
        assert_eq!((report.passed, report.skipped.len()), (26, 0));
    }
}

#[test]
fn fast_confirmation_minimal() {
    let runner = StoreReplay::<Minimal, Electra>::fast_confirmation();
    if let Some(report) = Suite::run(&runner, "minimal", "electra") {
        // Cases: basic 3, current epoch 22, empty slots 5, ffg 2, is one confirmed 19, previous epoch 108, reconfirmation 3, restart 6, revert finality 8, variables 8.
        assert_eq!((report.passed, report.skipped.len()), (184, 0));
    }
}

#[test]
fn sync_minimal() {
    let runner = StoreReplay::<Minimal, Electra>::sync();
    if let Some(report) = Suite::run(&runner, "minimal", "electra") {
        // Cases: optimistic 1.
        assert_eq!((report.passed, report.skipped.len()), (1, 0));
    }
}

#[test]
fn sync_mainnet() {
    let runner = StoreReplay::<Mainnet, Electra>::sync();
    if let Some(report) = Suite::run(&runner, "mainnet", "electra") {
        // Cases: optimistic 1.
        assert_eq!((report.passed, report.skipped.len()), (1, 0));
    }
}
