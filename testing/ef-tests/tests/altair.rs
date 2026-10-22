//! The Altair consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use axiom_ef_tests::{
    Blocks, EpochProcessing, Fork, LightClient, Networking, Operations, Rewards, SszStatic,
    StoreReplay, Suite, Transition,
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

#[test]
fn fork_choice_minimal() {
    let runner = StoreReplay::<Minimal, Altair>::fork_choice();
    if let Some(report) = Suite::run(&runner, "minimal", "altair") {
        // Cases: ex ante 3, get head 11, proposer head 3, on block 23, reorg 8, withholding 2.
        assert_eq!((report.passed, report.skipped.len()), (50, 0));
    }
}

#[test]
fn fork_choice_mainnet() {
    let runner = StoreReplay::<Mainnet, Altair>::fork_choice();
    if let Some(report) = Suite::run(&runner, "mainnet", "altair") {
        // Cases: ex ante 5, get head 7, proposer head 3, on block 6.
        assert_eq!((report.passed, report.skipped.len()), (21, 0));
    }
}

#[test]
fn fast_confirmation_minimal() {
    let runner = StoreReplay::<Minimal, Altair>::fast_confirmation();
    if let Some(report) = Suite::run(&runner, "minimal", "altair") {
        // Cases: basic 3, current epoch 22, empty slots 5, ffg 2, is one confirmed 10, previous epoch 108, reconfirmation 3, restart 6, revert finality 8, variables 8.
        assert_eq!((report.passed, report.skipped.len()), (175, 0));
    }
}
