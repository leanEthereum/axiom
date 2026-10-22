//! The Deneb consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Fork, LightClient, MerkleProofs, Networking, Operations, Rewards,
    SszStatic, StoreReplay, Suite, Transition,
    forks::{Capella, Deneb},
};
use axiom_types::{Mainnet, Minimal};

#[test]
fn ssz_static_minimal() {
    Suite::run(&SszStatic::<Minimal, Deneb>::default(), "minimal", "deneb");
}

#[test]
fn ssz_static_mainnet() {
    Suite::run(&SszStatic::<Mainnet, Deneb>::default(), "mainnet", "deneb");
}

#[test]
fn fork_minimal() {
    Suite::run(&Fork::<Minimal, Deneb>::default(), "minimal", "deneb");
}

#[test]
fn fork_mainnet() {
    Suite::run(&Fork::<Mainnet, Deneb>::default(), "mainnet", "deneb");
}

#[test]
fn networking_minimal() {
    Suite::run(&Networking::<Minimal, Deneb>::default(), "minimal", "deneb");
}

#[test]
fn networking_mainnet() {
    Suite::run(&Networking::<Mainnet, Deneb>::default(), "mainnet", "deneb");
}

#[test]
fn light_client_minimal() {
    let runner = LightClient::<Minimal, Deneb>::default();
    if let Some(report) = Suite::run(&runner, "minimal", "deneb") {
        // Cases: sync 8, update ranking 1, merkle proofs 4, data collection 1.
        assert_eq!((report.passed, report.skipped.len()), (14, 0));
    }
}

#[test]
fn light_client_mainnet() {
    let runner = LightClient::<Mainnet, Deneb>::default();
    if let Some(report) = Suite::run(&runner, "mainnet", "deneb") {
        // Cases: merkle proofs 4.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}

#[test]
fn merkle_proof_minimal() {
    let runner = MerkleProofs::<Minimal, Deneb>::merkle_proof();
    if let Some(report) = Suite::run(&runner, "minimal", "deneb") {
        // Cases: four blob commitment proofs into the block body.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}

#[test]
fn merkle_proof_mainnet() {
    let runner = MerkleProofs::<Mainnet, Deneb>::merkle_proof();
    if let Some(report) = Suite::run(&runner, "mainnet", "deneb") {
        // Cases: four blob commitment proofs into the block body.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}

#[test]
fn operations_minimal() {
    Suite::run(&Operations::<Minimal, Deneb>::default(), "minimal", "deneb");
}

#[test]
fn operations_mainnet() {
    Suite::run(&Operations::<Mainnet, Deneb>::default(), "mainnet", "deneb");
}

#[test]
fn epoch_processing_minimal() {
    Suite::run(
        &EpochProcessing::<Minimal, Deneb>::default(),
        "minimal",
        "deneb",
    );
}

#[test]
fn epoch_processing_mainnet() {
    Suite::run(
        &EpochProcessing::<Mainnet, Deneb>::default(),
        "mainnet",
        "deneb",
    );
}

#[test]
fn sanity_minimal() {
    Suite::run(&Blocks::<Minimal, Deneb>::sanity(), "minimal", "deneb");
}

#[test]
fn sanity_mainnet() {
    Suite::run(&Blocks::<Mainnet, Deneb>::sanity(), "mainnet", "deneb");
}

#[test]
fn finality_minimal() {
    Suite::run(&Blocks::<Minimal, Deneb>::finality(), "minimal", "deneb");
}

#[test]
fn finality_mainnet() {
    Suite::run(&Blocks::<Mainnet, Deneb>::finality(), "mainnet", "deneb");
}

#[test]
fn random_minimal() {
    Suite::run(&Blocks::<Minimal, Deneb>::random(), "minimal", "deneb");
}

#[test]
fn random_mainnet() {
    Suite::run(&Blocks::<Mainnet, Deneb>::random(), "mainnet", "deneb");
}

#[test]
fn rewards_minimal() {
    Suite::run(&Rewards::<Minimal, Deneb>::default(), "minimal", "deneb");
}

#[test]
fn rewards_mainnet() {
    Suite::run(&Rewards::<Mainnet, Deneb>::default(), "mainnet", "deneb");
}

#[test]
fn transition_minimal() {
    Suite::run(
        &Transition::<Minimal, Capella, Deneb>::default(),
        "minimal",
        "deneb",
    );
}

#[test]
fn transition_mainnet() {
    Suite::run(
        &Transition::<Mainnet, Capella, Deneb>::default(),
        "mainnet",
        "deneb",
    );
}

#[test]
fn fork_choice_minimal() {
    let runner = StoreReplay::<Minimal, Deneb>::fork_choice();
    if let Some(report) = Suite::run(&runner, "minimal", "deneb") {
        // Cases: ex ante 3, get head 11, proposer head 3, on block 28, reorg 8, withholding 2.
        assert_eq!((report.passed, report.skipped.len()), (55, 0));
    }
}

#[test]
fn fork_choice_mainnet() {
    let runner = StoreReplay::<Mainnet, Deneb>::fork_choice();
    if let Some(report) = Suite::run(&runner, "mainnet", "deneb") {
        // Cases: ex ante 5, get head 7, proposer head 3, on block 11.
        assert_eq!((report.passed, report.skipped.len()), (26, 0));
    }
}

#[test]
fn fast_confirmation_minimal() {
    let runner = StoreReplay::<Minimal, Deneb>::fast_confirmation();
    if let Some(report) = Suite::run(&runner, "minimal", "deneb") {
        // Cases: basic 3, current epoch 22, empty slots 5, ffg 2, is one confirmed 10, previous epoch 108, reconfirmation 3, restart 6, revert finality 8, variables 8.
        assert_eq!((report.passed, report.skipped.len()), (175, 0));
    }
}

#[test]
fn sync_minimal() {
    let runner = StoreReplay::<Minimal, Deneb>::sync();
    if let Some(report) = Suite::run(&runner, "minimal", "deneb") {
        // Cases: optimistic 1.
        assert_eq!((report.passed, report.skipped.len()), (1, 0));
    }
}

#[test]
fn sync_mainnet() {
    let runner = StoreReplay::<Mainnet, Deneb>::sync();
    if let Some(report) = Suite::run(&runner, "mainnet", "deneb") {
        // Cases: optimistic 1.
        assert_eq!((report.passed, report.skipped.len()), (1, 0));
    }
}
