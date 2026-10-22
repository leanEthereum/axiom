//! The Capella consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use axiom_ef_tests::{Fork, SszStatic, Suite, forks::Capella};
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
