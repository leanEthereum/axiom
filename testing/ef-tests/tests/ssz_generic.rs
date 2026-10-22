//! The generic SSZ vectors of the consensus specs, one test per handler.
//!
//! They ship only in the general suite of an older release, pinned in the Makefile.
//! Each test pins its case count, so a shrinking vector set cannot pass silently.
//! No case is skipped: every valid and every invalid case runs.

use std::{env, fs};

use axiom_ef_tests::{Report, SszGeneric, Suite, Vectors};

/// Runs one handler and returns its tally, or nothing when the vectors are absent.
///
/// # Panics
///
/// Panics when a case fails or is skipped.
fn run(handler: &str) -> Option<Report> {
    let report = Suite::run_general(&SszGeneric, "phase0", handler)?;
    assert_eq!(report.skipped.len(), 0, "skipped: {:?}", report.skipped);
    Some(report)
}

#[test]
fn every_handler_is_tested() {
    let Some(vectors) = Vectors::locate() else {
        return;
    };
    let dir = vectors.general().join("phase0/ssz_generic");
    let Ok(entries) = fs::read_dir(&dir) else {
        assert!(
            env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
            "{} is missing",
            dir.display()
        );
        return;
    };

    // Ten handlers ship in the release, and each has a test below.
    let mut handlers: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    handlers.sort();
    assert_eq!(
        handlers,
        [
            "basic_progressive_list",
            "basic_vector",
            "bitlist",
            "bitvector",
            "boolean",
            "compatible_unions",
            "containers",
            "progressive_bitlist",
            "progressive_containers",
            "uints",
        ]
    );
}

#[test]
fn boolean() {
    let Some(report) = run("boolean") else {
        return;
    };

    // Two valid bytes, 0 and 1, and four invalid ones.
    assert_eq!(report.passed, 6);
}

#[test]
fn uints() {
    let Some(report) = run("uints") else {
        return;
    };

    // Six widths: eight valid and three invalid cases each.
    assert_eq!(report.passed, 66);
}

#[test]
fn basic_vector() {
    let Some(report) = run("basic_vector") else {
        return;
    };

    // 200 valid and 957 invalid cases.
    // Seven invalid cases declare a zero-length vector, one per element type.
    assert_eq!(report.passed, 1157);
}

#[test]
fn bitlist() {
    let Some(report) = run("bitlist") else {
        return;
    };

    // 450 valid and 44 invalid cases.
    assert_eq!(report.passed, 494);
}

#[test]
fn bitvector() {
    let Some(report) = run("bitvector") else {
        return;
    };

    // 54 valid and 31 invalid cases, one of them declaring a zero-length bitvector.
    assert_eq!(report.passed, 85);
}

#[test]
fn containers() {
    let Some(report) = run("containers") else {
        return;
    };

    // Eight test containers, two of them holding progressive fields.
    // They give 463 valid and 238 invalid cases.
    assert_eq!(report.passed, 701);
}

#[test]
fn basic_progressive_list() {
    let Some(report) = run("basic_progressive_list") else {
        return;
    };

    // Seven element types give 320 valid and 567 invalid cases.
    assert_eq!(report.passed, 887);
}

#[test]
fn compatible_unions() {
    let Some(report) = run("compatible_unions") else {
        return;
    };

    // Three unions of progressive containers give 210 valid and 311 invalid cases.
    assert_eq!(report.passed, 521);
}

#[test]
fn progressive_bitlist() {
    let Some(report) = run("progressive_bitlist") else {
        return;
    };

    // 700 valid and 3 invalid cases.
    assert_eq!(report.passed, 703);
}

#[test]
fn progressive_containers() {
    let Some(report) = run("progressive_containers") else {
        return;
    };

    // Four progressive containers give 261 valid and 264 invalid cases.
    assert_eq!(report.passed, 525);
}
