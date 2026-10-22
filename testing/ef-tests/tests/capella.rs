//! The Capella consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use axiom_ef_tests::{Fork, LightClient, Networking, SszStatic, Suite, forks::Capella};
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
