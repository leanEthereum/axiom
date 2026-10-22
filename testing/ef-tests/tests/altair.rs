//! The Altair consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.
//!
//! The fork choice and sync runners belong to other suites.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Fork, LightClient, Networking, Operations, Rewards, SszStatic, Suite,
    Transition,
    forks::{Altair, Phase0},
};
use axiom_types::{Mainnet, Minimal};

#[test]
fn ssz_static_minimal() {
    Suite::run(
        &SszStatic::<Minimal, Altair>::default(),
        "minimal",
        "altair",
    );
}

#[test]
fn ssz_static_mainnet() {
    Suite::run(
        &SszStatic::<Mainnet, Altair>::default(),
        "mainnet",
        "altair",
    );
}

#[test]
fn operations_minimal() {
    Suite::run(
        &Operations::<Minimal, Altair>::default(),
        "minimal",
        "altair",
    );
}

#[test]
fn operations_mainnet() {
    Suite::run(
        &Operations::<Mainnet, Altair>::default(),
        "mainnet",
        "altair",
    );
}

#[test]
fn epoch_processing_minimal() {
    Suite::run(
        &EpochProcessing::<Minimal, Altair>::default(),
        "minimal",
        "altair",
    );
}

#[test]
fn epoch_processing_mainnet() {
    Suite::run(
        &EpochProcessing::<Mainnet, Altair>::default(),
        "mainnet",
        "altair",
    );
}

#[test]
fn sanity_minimal() {
    Suite::run(&Blocks::<Minimal, Altair>::sanity(), "minimal", "altair");
}

#[test]
fn sanity_mainnet() {
    Suite::run(&Blocks::<Mainnet, Altair>::sanity(), "mainnet", "altair");
}

#[test]
fn finality_minimal() {
    Suite::run(&Blocks::<Minimal, Altair>::finality(), "minimal", "altair");
}

#[test]
fn finality_mainnet() {
    Suite::run(&Blocks::<Mainnet, Altair>::finality(), "mainnet", "altair");
}

#[test]
fn random_minimal() {
    Suite::run(&Blocks::<Minimal, Altair>::random(), "minimal", "altair");
}

#[test]
fn random_mainnet() {
    Suite::run(&Blocks::<Mainnet, Altair>::random(), "mainnet", "altair");
}

#[test]
fn rewards_minimal() {
    Suite::run(&Rewards::<Minimal, Altair>::default(), "minimal", "altair");
}

#[test]
fn rewards_mainnet() {
    Suite::run(&Rewards::<Mainnet, Altair>::default(), "mainnet", "altair");
}

#[test]
fn fork_minimal() {
    Suite::run(&Fork::<Minimal, Altair>::default(), "minimal", "altair");
}

#[test]
fn fork_mainnet() {
    Suite::run(&Fork::<Mainnet, Altair>::default(), "mainnet", "altair");
}

#[test]
fn transition_minimal() {
    Suite::run(
        &Transition::<Minimal, Phase0, Altair>::default(),
        "minimal",
        "altair",
    );
}

#[test]
fn transition_mainnet() {
    Suite::run(
        &Transition::<Mainnet, Phase0, Altair>::default(),
        "mainnet",
        "altair",
    );
}

#[test]
fn networking_minimal() {
    Suite::run(
        &Networking::<Minimal, Altair>::default(),
        "minimal",
        "altair",
    );
}

#[test]
fn networking_mainnet() {
    Suite::run(
        &Networking::<Mainnet, Altair>::default(),
        "mainnet",
        "altair",
    );
}

#[test]
fn light_client_minimal() {
    let runner = LightClient::<Minimal, Altair>::default();
    if let Some(report) = Suite::run(&runner, "minimal", "altair") {
        // Cases: sync 8, update ranking 1, merkle proofs 3, data collection 1.
        assert_eq!((report.passed, report.skipped.len()), (13, 0));
    }
}

#[test]
fn light_client_mainnet() {
    let runner = LightClient::<Mainnet, Altair>::default();
    if let Some(report) = Suite::run(&runner, "mainnet", "altair") {
        // Cases: merkle proofs 3.
        assert_eq!((report.passed, report.skipped.len()), (3, 0));
    }
}
