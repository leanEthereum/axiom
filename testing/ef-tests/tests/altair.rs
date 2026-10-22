//! The Altair consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.
//!
//! The fork choice, light client, networking, and sync runners belong to other suites.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Fork, Operations, Rewards, SszStatic, Suite, Transition,
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
