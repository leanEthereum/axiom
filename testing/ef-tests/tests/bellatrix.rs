//! The Bellatrix consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.
//!
//! The fork choice and sync runners belong to other suites.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Fork, LightClient, Networking, Operations, Rewards, SszStatic, Suite,
    Transition,
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
