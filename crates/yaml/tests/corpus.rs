//! Parses every YAML file of the consensus, BLS, and KZG test vectors.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use axiom_yaml::Yaml;

/// Directory of the downloaded vectors, if present.
///
/// The `AXIOM_VECTORS` variable wins.
/// Otherwise the nearest ancestor holding `testing/vectors` is used.
/// Vectors are gitignored, so a git worktree finds them in the main checkout above it.
fn vectors_dir() -> Option<PathBuf> {
    if let Some(dir) = env::var_os("AXIOM_VECTORS") {
        return Some(PathBuf::from(dir));
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .map(|dir| dir.join("testing/vectors"))
        .find(|dir| dir.is_dir())
}

/// Every file with the given extension below a directory, sorted for stable reports.
fn files_with_extension(root: &Path, extension: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).expect("vector directory is readable") {
            let path = entry.expect("directory entry is readable").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|e| e == extension) {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// Parses and round-trips every YAML file below a directory, returning how many it read.
fn round_trip_every_file(dir: &Path) -> usize {
    let files = files_with_extension(dir, "yaml");
    for path in &files {
        let text = fs::read_to_string(path).expect("vector file is readable");
        let value = Yaml::parse(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()));

        // Law: what the emitter writes parses back to the same document.
        let emitted = value.to_string();
        assert_eq!(
            Yaml::parse(&emitted).as_ref(),
            Ok(&value),
            "{}: emitted text does not parse back",
            path.display()
        );
    }
    files.len()
}

#[test]
fn parses_every_vector_file_and_round_trips_it() {
    let Some(root) = vectors_dir() else {
        assert!(
            env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
            "vectors required but missing; run `make -C testing/ef-tests`"
        );
        println!("skipped: no testing/vectors found; set AXIOM_VECTORS to run the corpus");
        return;
    };

    // Each vector root, with its exact number of YAML files.
    let expected = [
        ("consensus-spec-tests/tests", 207_098),
        ("bls12-381-tests", 98),
        ("kzg/tests", 344),
    ];
    let actual = expected.map(|(dir, _)| (dir, round_trip_every_file(&root.join(dir))));
    assert_eq!(actual, expected);

    // Extra directories listed in AXIOM_YAML_EXTRA, colon-separated, parse too.
    //
    //     AXIOM_YAML_EXTRA=specs/configs:specs/presets
    if let Some(extra) = env::var_os("AXIOM_YAML_EXTRA") {
        for dir in env::split_paths(&extra) {
            round_trip_every_file(&dir);
        }
    }
}
