//! The Bellatrix consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.
//!
//! The fork choice, light client, networking, and sync runners belong to other suites.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Fork, Operations, Rewards, SszStatic, Suite, Transition,
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
