//! The Capella consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Fork, LightClient, Networking, Operations, Rewards, SszStatic,
    StoreReplay, Suite, Transition,
    forks::{Bellatrix, Capella},
};
use axiom_types::{Mainnet, Minimal};

#[test]
fn ssz_static_minimal() {
    Suite::run(
        &SszStatic::<Minimal, Capella>::default(),
        "minimal",
        "capella",
    );
}

#[test]
fn ssz_static_mainnet() {
    Suite::run(
        &SszStatic::<Mainnet, Capella>::default(),
        "mainnet",
        "capella",
    );
}

#[test]
fn fork_minimal() {
    Suite::run(&Fork::<Minimal, Capella>::default(), "minimal", "capella");
}

#[test]
fn fork_mainnet() {
    Suite::run(&Fork::<Mainnet, Capella>::default(), "mainnet", "capella");
}

#[test]
fn networking_minimal() {
    Suite::run(
        &Networking::<Minimal, Capella>::default(),
        "minimal",
        "capella",
    );
}

#[test]
fn networking_mainnet() {
    Suite::run(
        &Networking::<Mainnet, Capella>::default(),
        "mainnet",
        "capella",
    );
}

#[test]
fn light_client_minimal() {
    let runner = LightClient::<Minimal, Capella>::default();
    if let Some(report) = Suite::run(&runner, "minimal", "capella") {
        // Cases: sync 10, update ranking 1, merkle proofs 4, data collection 3.
        assert_eq!((report.passed, report.skipped.len()), (18, 0));
    }
}

#[test]
fn light_client_mainnet() {
    let runner = LightClient::<Mainnet, Capella>::default();
    if let Some(report) = Suite::run(&runner, "mainnet", "capella") {
        // Cases: merkle proofs 4.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}

#[test]
fn operations_minimal() {
    Suite::run(
        &Operations::<Minimal, Capella>::default(),
        "minimal",
        "capella",
    );
}

#[test]
fn operations_mainnet() {
    Suite::run(
        &Operations::<Mainnet, Capella>::default(),
        "mainnet",
        "capella",
    );
}

#[test]
fn epoch_processing_minimal() {
    Suite::run(
        &EpochProcessing::<Minimal, Capella>::default(),
        "minimal",
        "capella",
    );
}

#[test]
fn epoch_processing_mainnet() {
    Suite::run(
        &EpochProcessing::<Mainnet, Capella>::default(),
        "mainnet",
        "capella",
    );
}

#[test]
fn sanity_minimal() {
    Suite::run(&Blocks::<Minimal, Capella>::sanity(), "minimal", "capella");
}

#[test]
fn sanity_mainnet() {
    Suite::run(&Blocks::<Mainnet, Capella>::sanity(), "mainnet", "capella");
}

#[test]
fn finality_minimal() {
    Suite::run(
        &Blocks::<Minimal, Capella>::finality(),
        "minimal",
        "capella",
    );
}

#[test]
fn finality_mainnet() {
    Suite::run(
        &Blocks::<Mainnet, Capella>::finality(),
        "mainnet",
        "capella",
    );
}

#[test]
fn random_minimal() {
    Suite::run(&Blocks::<Minimal, Capella>::random(), "minimal", "capella");
}

#[test]
fn random_mainnet() {
    Suite::run(&Blocks::<Mainnet, Capella>::random(), "mainnet", "capella");
}

#[test]
fn rewards_minimal() {
    Suite::run(
        &Rewards::<Minimal, Capella>::default(),
        "minimal",
        "capella",
    );
}

#[test]
fn rewards_mainnet() {
    Suite::run(
        &Rewards::<Mainnet, Capella>::default(),
        "mainnet",
        "capella",
    );
}

#[test]
fn transition_minimal() {
    Suite::run(
        &Transition::<Minimal, Bellatrix, Capella>::default(),
        "minimal",
        "capella",
    );
}

#[test]
fn transition_mainnet() {
    Suite::run(
        &Transition::<Mainnet, Bellatrix, Capella>::default(),
        "mainnet",
        "capella",
    );
}

#[test]
fn fork_choice_minimal() {
    let runner = StoreReplay::<Minimal, Capella>::fork_choice();
    if let Some(report) = Suite::run(&runner, "minimal", "capella") {
        // Cases: ex ante 3, get head 11, proposer head 3, on block 23, reorg 8, withholding 2.
        assert_eq!((report.passed, report.skipped.len()), (50, 0));
    }
}

#[test]
fn fork_choice_mainnet() {
    let runner = StoreReplay::<Mainnet, Capella>::fork_choice();
    if let Some(report) = Suite::run(&runner, "mainnet", "capella") {
        // Cases: ex ante 5, get head 7, proposer head 3, on block 6.
        assert_eq!((report.passed, report.skipped.len()), (21, 0));
    }
}

#[test]
fn fast_confirmation_minimal() {
    let runner = StoreReplay::<Minimal, Capella>::fast_confirmation();
    if let Some(report) = Suite::run(&runner, "minimal", "capella") {
        // Cases: basic 3, current epoch 22, empty slots 5, ffg 2, is one confirmed 10, previous epoch 108, reconfirmation 3, restart 6, revert finality 8, variables 8.
        assert_eq!((report.passed, report.skipped.len()), (175, 0));
    }
}

#[test]
fn sync_minimal() {
    let runner = StoreReplay::<Minimal, Capella>::sync();
    if let Some(report) = Suite::run(&runner, "minimal", "capella") {
        // Cases: optimistic 1.
        assert_eq!((report.passed, report.skipped.len()), (1, 0));
    }
}

#[test]
fn sync_mainnet() {
    let runner = StoreReplay::<Mainnet, Capella>::sync();
    if let Some(report) = Suite::run(&runner, "mainnet", "capella") {
        // Cases: optimistic 1.
        assert_eq!((report.passed, report.skipped.len()), (1, 0));
    }
}
