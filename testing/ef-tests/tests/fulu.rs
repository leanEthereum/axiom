//! The Fulu consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Fork, LightClient, MerkleProofs, Networking, Operations, Rewards,
    Shuffling, SszStatic, StoreReplay, Suite, Transition,
};
use axiom_types::{Mainnet, Minimal};

#[test]
fn ssz_static_minimal() {
    Suite::run(&SszStatic::<Minimal>::default(), "minimal", "fulu");
}

#[test]
fn ssz_static_mainnet() {
    Suite::run(&SszStatic::<Mainnet>::default(), "mainnet", "fulu");
}

#[test]
fn operations_minimal() {
    Suite::run(&Operations::<Minimal>::default(), "minimal", "fulu");
}

#[test]
fn operations_mainnet() {
    Suite::run(&Operations::<Mainnet>::default(), "mainnet", "fulu");
}

#[test]
fn epoch_processing_minimal() {
    Suite::run(&EpochProcessing::<Minimal>::default(), "minimal", "fulu");
}

#[test]
fn epoch_processing_mainnet() {
    Suite::run(&EpochProcessing::<Mainnet>::default(), "mainnet", "fulu");
}

#[test]
fn sanity_minimal() {
    Suite::run(&Blocks::<Minimal>::sanity(), "minimal", "fulu");
}

#[test]
fn sanity_mainnet() {
    Suite::run(&Blocks::<Mainnet>::sanity(), "mainnet", "fulu");
}

#[test]
fn finality_minimal() {
    Suite::run(&Blocks::<Minimal>::finality(), "minimal", "fulu");
}

#[test]
fn finality_mainnet() {
    Suite::run(&Blocks::<Mainnet>::finality(), "mainnet", "fulu");
}

#[test]
fn random_minimal() {
    Suite::run(&Blocks::<Minimal>::random(), "minimal", "fulu");
}

#[test]
fn random_mainnet() {
    Suite::run(&Blocks::<Mainnet>::random(), "mainnet", "fulu");
}

#[test]
fn rewards_minimal() {
    Suite::run(&Rewards::<Minimal>::default(), "minimal", "fulu");
}

#[test]
fn rewards_mainnet() {
    Suite::run(&Rewards::<Mainnet>::default(), "mainnet", "fulu");
}

#[test]
fn fork_minimal() {
    Suite::run(&Fork::<Minimal>::default(), "minimal", "fulu");
}

#[test]
fn fork_mainnet() {
    Suite::run(&Fork::<Mainnet>::default(), "mainnet", "fulu");
}

#[test]
fn transition_minimal() {
    Suite::run(&Transition::<Minimal>::default(), "minimal", "fulu");
}

#[test]
fn transition_mainnet() {
    Suite::run(&Transition::<Mainnet>::default(), "mainnet", "fulu");
}

#[test]
fn shuffling_minimal() {
    // Shuffling vectors exist only under phase0, and the shuffle never changed since.
    Suite::run(&Shuffling::<Minimal>::default(), "minimal", "phase0");
}

#[test]
fn shuffling_mainnet() {
    Suite::run(&Shuffling::<Mainnet>::default(), "mainnet", "phase0");
}

#[test]
fn fork_choice_minimal() {
    Suite::run(&StoreReplay::<Minimal>::fork_choice(), "minimal", "fulu");
}

#[test]
fn fork_choice_mainnet() {
    Suite::run(&StoreReplay::<Mainnet>::fork_choice(), "mainnet", "fulu");
}

#[test]
fn networking_minimal() {
    Suite::run(&Networking::<Minimal>::default(), "minimal", "fulu");
}

#[test]
fn networking_mainnet() {
    Suite::run(&Networking::<Mainnet>::default(), "mainnet", "fulu");
}

#[test]
fn merkle_proof_minimal() {
    Suite::run(&MerkleProofs::<Minimal>::merkle_proof(), "minimal", "fulu");
}

#[test]
fn merkle_proof_mainnet() {
    Suite::run(&MerkleProofs::<Mainnet>::merkle_proof(), "mainnet", "fulu");
}

#[test]
fn light_client_minimal() {
    Suite::run(&LightClient::<Minimal>::default(), "minimal", "fulu");
}

#[test]
fn light_client_mainnet() {
    Suite::run(&LightClient::<Mainnet>::default(), "mainnet", "fulu");
}

#[test]
fn fast_confirmation_minimal() {
    Suite::run(
        &StoreReplay::<Minimal>::fast_confirmation(),
        "minimal",
        "fulu",
    );
}

#[test]
fn sync_minimal() {
    Suite::run(&StoreReplay::<Minimal>::sync(), "minimal", "fulu");
}

#[test]
fn sync_mainnet() {
    Suite::run(&StoreReplay::<Mainnet>::sync(), "mainnet", "fulu");
}
