//! The generic SSZ vectors of the consensus specs, one test per handler.
//!
//! They ship only in the general suite of an older release, pinned in the Makefile.
//! Each test pins its case counts, so a shrinking vector set cannot pass silently.

use std::{env, fs};

use axiom_ef_tests::{Report, SszGeneric, Suite, Vectors};

/// Runs one handler and returns its tally, or nothing when the vectors are absent.
fn run(handler: &str) -> Option<Report> {
    Suite::run_general(&SszGeneric, "phase0", handler)
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
    assert_eq!(report.skipped.len(), 0);
}

#[test]
fn uints() {
    let Some(report) = run("uints") else {
        return;
    };

    // Six widths: eight valid and three invalid cases each.
    assert_eq!(report.passed, 66);
    assert_eq!(report.skipped.len(), 0);
}

#[test]
fn basic_vector() {
    let Some(report) = run("basic_vector") else {
        return;
    };

    // 200 valid and 950 invalid cases run.
    assert_eq!(report.passed, 1150);

    // One zero-length vector per element type, seven in all, cannot be written as a type.
    assert_eq!(report.skipped.len(), 7);
}

#[test]
fn bitlist() {
    let Some(report) = run("bitlist") else {
        return;
    };

    // 450 valid and 44 invalid cases.
    assert_eq!(report.passed, 494);
    assert_eq!(report.skipped.len(), 0);
}

#[test]
fn bitvector() {
    let Some(report) = run("bitvector") else {
        return;
    };

    // 54 valid and 30 invalid cases run.
    assert_eq!(report.passed, 84);

    // The zero-length bitvector cannot be written as a type.
    assert_eq!(report.skipped.len(), 1);
}

#[test]
fn containers() {
    let Some(report) = run("containers") else {
        return;
    };

    // Six test containers give 303 valid and 104 invalid cases.
    assert_eq!(report.passed, 407);

    // Two progressive containers give 160 valid and 134 invalid cases, not run.
    assert_eq!(report.skipped.len(), 294);
}

#[test]
fn basic_progressive_list() {
    let Some(report) = run("basic_progressive_list") else {
        return;
    };

    // Progressive lists are not part of Fulu: 320 valid and 567 invalid cases, not run.
    assert_eq!(report.passed, 0);
    assert_eq!(report.skipped.len(), 887);
}

#[test]
fn compatible_unions() {
    let Some(report) = run("compatible_unions") else {
        return;
    };

    // Compatible unions are not part of Fulu: 210 valid and 311 invalid cases, not run.
    assert_eq!(report.passed, 0);
    assert_eq!(report.skipped.len(), 521);
}

#[test]
fn progressive_bitlist() {
    let Some(report) = run("progressive_bitlist") else {
        return;
    };

    // Progressive bitlists are not part of Fulu: 700 valid and 3 invalid cases, not run.
    assert_eq!(report.passed, 0);
    assert_eq!(report.skipped.len(), 703);
}

#[test]
fn progressive_containers() {
    let Some(report) = run("progressive_containers") else {
        return;
    };

    // Progressive containers are not part of Fulu: 261 valid and 264 invalid cases, not run.
    assert_eq!(report.passed, 0);
    assert_eq!(report.skipped.len(), 525);
}
