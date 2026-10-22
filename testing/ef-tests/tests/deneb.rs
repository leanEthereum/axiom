//! The Deneb consensus spec vectors, for both presets.
//!
//! Each test runs one runner over every handler and case it finds.
//! A handler this client does not know fails the test, so no vector is skipped silently.

use axiom_ef_tests::{Fork, LightClient, MerkleProofs, Networking, SszStatic, Suite, forks::Deneb};
use axiom_types::{Mainnet, Minimal};

#[test]
fn ssz_static_minimal() {
    Suite::run(&SszStatic::<Minimal, Deneb>::default(), "minimal", "deneb");
}

#[test]
fn ssz_static_mainnet() {
    Suite::run(&SszStatic::<Mainnet, Deneb>::default(), "mainnet", "deneb");
}

#[test]
fn fork_minimal() {
    Suite::run(&Fork::<Minimal, Deneb>::default(), "minimal", "deneb");
}

#[test]
fn fork_mainnet() {
    Suite::run(&Fork::<Mainnet, Deneb>::default(), "mainnet", "deneb");
}

#[test]
fn networking_minimal() {
    Suite::run(&Networking::<Minimal, Deneb>::default(), "minimal", "deneb");
}

#[test]
fn networking_mainnet() {
    Suite::run(&Networking::<Mainnet, Deneb>::default(), "mainnet", "deneb");
}

#[test]
fn light_client_minimal() {
    let runner = LightClient::<Minimal, Deneb>::default();
    if let Some(report) = Suite::run(&runner, "minimal", "deneb") {
        // Cases: sync 8, update ranking 1, merkle proofs 4, data collection 1.
        assert_eq!((report.passed, report.skipped.len()), (14, 0));
    }
}

#[test]
fn light_client_mainnet() {
    let runner = LightClient::<Mainnet, Deneb>::default();
    if let Some(report) = Suite::run(&runner, "mainnet", "deneb") {
        // Cases: merkle proofs 4.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}

#[test]
fn merkle_proof_minimal() {
    let runner = MerkleProofs::<Minimal, Deneb>::merkle_proof();
    if let Some(report) = Suite::run(&runner, "minimal", "deneb") {
        // Cases: four blob commitment proofs into the block body.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}

#[test]
fn merkle_proof_mainnet() {
    let runner = MerkleProofs::<Mainnet, Deneb>::merkle_proof();
    if let Some(report) = Suite::run(&runner, "mainnet", "deneb") {
        // Cases: four blob commitment proofs into the block body.
        assert_eq!((report.passed, report.skipped.len()), (4, 0));
    }
}
