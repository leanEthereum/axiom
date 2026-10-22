//! The Bellatrix consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Fork, LightClient, Networking, Operations, Rewards, SszStatic,
    StoreReplay, Suite, Transition,
    forks::{Altair, Bellatrix},
};
use axiom_types::{Mainnet, Minimal};

#[test]
fn ssz_static_minimal() {
    Suite::run(
        &SszStatic::<Minimal, Bellatrix>::default(),
        "minimal",
        "bellatrix",
    );
}

#[test]
fn ssz_static_mainnet() {
    Suite::run(
        &SszStatic::<Mainnet, Bellatrix>::default(),
        "mainnet",
        "bellatrix",
    );
}

#[test]
fn operations_minimal() {
    Suite::run(
        &Operations::<Minimal, Bellatrix>::default(),
        "minimal",
        "bellatrix",
    );
}

#[test]
fn operations_mainnet() {
    Suite::run(
        &Operations::<Mainnet, Bellatrix>::default(),
        "mainnet",
        "bellatrix",
    );
}

#[test]
fn epoch_processing_minimal() {
    Suite::run(
        &EpochProcessing::<Minimal, Bellatrix>::default(),
        "minimal",
        "bellatrix",
    );
}

#[test]
fn epoch_processing_mainnet() {
    Suite::run(
        &EpochProcessing::<Mainnet, Bellatrix>::default(),
        "mainnet",
        "bellatrix",
    );
}

#[test]
fn sanity_minimal() {
    Suite::run(
        &Blocks::<Minimal, Bellatrix>::sanity(),
        "minimal",
        "bellatrix",
    );
}

#[test]
fn sanity_mainnet() {
    Suite::run(
        &Blocks::<Mainnet, Bellatrix>::sanity(),
        "mainnet",
        "bellatrix",
    );
}

#[test]
fn finality_minimal() {
    Suite::run(
        &Blocks::<Minimal, Bellatrix>::finality(),
        "minimal",
        "bellatrix",
    );
}

#[test]
fn finality_mainnet() {
    Suite::run(
        &Blocks::<Mainnet, Bellatrix>::finality(),
        "mainnet",
        "bellatrix",
    );
}

#[test]
fn random_minimal() {
    Suite::run(
        &Blocks::<Minimal, Bellatrix>::random(),
        "minimal",
        "bellatrix",
    );
}

#[test]
fn random_mainnet() {
    Suite::run(
        &Blocks::<Mainnet, Bellatrix>::random(),
        "mainnet",
        "bellatrix",
    );
}

#[test]
fn rewards_minimal() {
    Suite::run(
        &Rewards::<Minimal, Bellatrix>::default(),
        "minimal",
        "bellatrix",
    );
}

#[test]
fn rewards_mainnet() {
    Suite::run(
        &Rewards::<Mainnet, Bellatrix>::default(),
        "mainnet",
        "bellatrix",
    );
}

#[test]
fn fork_minimal() {
    Suite::run(
        &Fork::<Minimal, Bellatrix>::default(),
        "minimal",
        "bellatrix",
    );
}

#[test]
fn fork_mainnet() {
    Suite::run(
        &Fork::<Mainnet, Bellatrix>::default(),
        "mainnet",
        "bellatrix",
    );
}

#[test]
fn transition_minimal() {
    Suite::run(
        &Transition::<Minimal, Altair, Bellatrix>::default(),
        "minimal",
        "bellatrix",
    );
}

#[test]
fn transition_mainnet() {
    Suite::run(
        &Transition::<Mainnet, Altair, Bellatrix>::default(),
        "mainnet",
        "bellatrix",
    );
}

#[test]
fn networking_minimal() {
    Suite::run(
        &Networking::<Minimal, Bellatrix>::default(),
        "minimal",
        "bellatrix",
    );
}

#[test]
fn networking_mainnet() {
    Suite::run(
        &Networking::<Mainnet, Bellatrix>::default(),
        "mainnet",
        "bellatrix",
    );
}

#[test]
fn light_client_minimal() {
    let runner = LightClient::<Minimal, Bellatrix>::default();
    if let Some(report) = Suite::run(&runner, "minimal", "bellatrix") {
        // Cases: sync 11, update ranking 1, merkle proofs 3, data collection 3.
        assert_eq!((report.passed, report.skipped.len()), (18, 0));
    }
}

#[test]
fn light_client_mainnet() {
    let runner = LightClient::<Mainnet, Bellatrix>::default();
    if let Some(report) = Suite::run(&runner, "mainnet", "bellatrix") {
        // Cases: merkle proofs 3.
        assert_eq!((report.passed, report.skipped.len()), (3, 0));
    }
}

#[test]
fn fork_choice_minimal() {
    let runner = StoreReplay::<Minimal, Bellatrix>::fork_choice();
    if let Some(report) = Suite::run(&runner, "minimal", "bellatrix") {
        // Cases: ex ante 3, get head 11, proposer head 3, on block 23, on merge block 4, reorg 8, withholding 2.
        assert_eq!((report.passed, report.skipped.len()), (54, 0));
    }
}

#[test]
fn fork_choice_mainnet() {
    let runner = StoreReplay::<Mainnet, Bellatrix>::fork_choice();
    if let Some(report) = Suite::run(&runner, "mainnet", "bellatrix") {
        // Cases: ex ante 5, get head 7, proposer head 3, on block 6, on merge block 4.
        assert_eq!((report.passed, report.skipped.len()), (25, 0));
    }
}

#[test]
fn fast_confirmation_minimal() {
    let runner = StoreReplay::<Minimal, Bellatrix>::fast_confirmation();
    if let Some(report) = Suite::run(&runner, "minimal", "bellatrix") {
        // Cases: basic 3, current epoch 22, empty slots 5, ffg 2, is one confirmed 10, previous epoch 108, reconfirmation 3, restart 6, revert finality 8, variables 8.
        assert_eq!((report.passed, report.skipped.len()), (175, 0));
    }
}

#[test]
fn sync_minimal() {
    let runner = StoreReplay::<Minimal, Bellatrix>::sync();
    if let Some(report) = Suite::run(&runner, "minimal", "bellatrix") {
        // Cases: optimistic 1.
        assert_eq!((report.passed, report.skipped.len()), (1, 0));
    }
}

#[test]
fn sync_mainnet() {
    let runner = StoreReplay::<Mainnet, Bellatrix>::sync();
    if let Some(report) = Suite::run(&runner, "mainnet", "bellatrix") {
        // Cases: optimistic 1.
        assert_eq!((report.passed, report.skipped.len()), (1, 0));
    }
}
