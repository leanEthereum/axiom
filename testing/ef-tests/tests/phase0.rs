//! The phase0 consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.
//! The fork choice and networking vectors run in their own suites.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Genesis, Networking, Operations, PendingAttestationRewards, Shuffling,
    SszStatic, Suite, forks::Phase0,
};
use axiom_types::{Mainnet, Minimal};

#[test]
fn ssz_static_minimal() {
    Suite::run(
        &SszStatic::<Minimal, Phase0>::default(),
        "minimal",
        "phase0",
    );
}

#[test]
fn ssz_static_mainnet() {
    Suite::run(
        &SszStatic::<Mainnet, Phase0>::default(),
        "mainnet",
        "phase0",
    );
}

#[test]
fn operations_minimal() {
    Suite::run(
        &Operations::<Minimal, Phase0>::default(),
        "minimal",
        "phase0",
    );
}

#[test]
fn operations_mainnet() {
    Suite::run(
        &Operations::<Mainnet, Phase0>::default(),
        "mainnet",
        "phase0",
    );
}

#[test]
fn epoch_processing_minimal() {
    Suite::run(
        &EpochProcessing::<Minimal, Phase0>::default(),
        "minimal",
        "phase0",
    );
}

#[test]
fn epoch_processing_mainnet() {
    Suite::run(
        &EpochProcessing::<Mainnet, Phase0>::default(),
        "mainnet",
        "phase0",
    );
}

#[test]
fn sanity_minimal() {
    Suite::run(&Blocks::<Minimal, Phase0>::sanity(), "minimal", "phase0");
}

#[test]
fn sanity_mainnet() {
    Suite::run(&Blocks::<Mainnet, Phase0>::sanity(), "mainnet", "phase0");
}

#[test]
fn finality_minimal() {
    Suite::run(&Blocks::<Minimal, Phase0>::finality(), "minimal", "phase0");
}

#[test]
fn finality_mainnet() {
    Suite::run(&Blocks::<Mainnet, Phase0>::finality(), "mainnet", "phase0");
}

#[test]
fn random_minimal() {
    Suite::run(&Blocks::<Minimal, Phase0>::random(), "minimal", "phase0");
}

#[test]
fn random_mainnet() {
    Suite::run(&Blocks::<Mainnet, Phase0>::random(), "mainnet", "phase0");
}

#[test]
fn rewards_minimal() {
    Suite::run(
        &PendingAttestationRewards::<Minimal>::default(),
        "minimal",
        "phase0",
    );
}

#[test]
fn rewards_mainnet() {
    Suite::run(
        &PendingAttestationRewards::<Mainnet>::default(),
        "mainnet",
        "phase0",
    );
}

#[test]
fn shuffling_minimal() {
    Suite::run(&Shuffling::<Minimal>::default(), "minimal", "phase0");
}

#[test]
fn shuffling_mainnet() {
    Suite::run(&Shuffling::<Mainnet>::default(), "mainnet", "phase0");
}

#[test]
fn genesis_minimal() {
    // Only the minimal preset ships genesis vectors.
    Suite::run(&Genesis::<Minimal>::default(), "minimal", "phase0");
}

#[test]
fn networking_minimal() {
    Suite::run(
        &Networking::<Minimal, Phase0>::default(),
        "minimal",
        "phase0",
    );
}

#[test]
fn networking_mainnet() {
    Suite::run(
        &Networking::<Mainnet, Phase0>::default(),
        "mainnet",
        "phase0",
    );
}
