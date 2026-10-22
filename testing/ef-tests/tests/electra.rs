//! The Electra consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Fork, Operations, Rewards, SszStatic, Suite, Transition,
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
