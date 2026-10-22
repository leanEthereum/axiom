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

#[test]
fn parses_every_vector_file_and_round_trips_it() {
    let Some(root) = vectors_dir() else {
        println!("skipped: no testing/vectors found; set AXIOM_VECTORS to run the corpus");
        return;
    };

    // Vector roots, plus any extra directories listed in AXIOM_YAML_EXTRA.
    //
    //     AXIOM_YAML_EXTRA=specs/configs:specs/presets   (colon-separated)
    let mut dirs = vec![
        root.join("consensus-spec-tests/tests"),
        root.join("bls12-381-tests"),
        root.join("kzg/tests"),
    ];
    if let Some(extra) = env::var_os("AXIOM_YAML_EXTRA") {
        dirs.extend(env::split_paths(&extra));
    }

    let mut total = 0;
    for dir in dirs.iter().filter(|dir| dir.is_dir()) {
        let files = files_with_extension(dir, "yaml");
        for path in &files {
            let text = fs::read_to_string(path).unwrap();
            let value =
                Yaml::parse(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()));

            // Law: what the emitter writes parses back to the same document.
            let emitted = value.to_string();
            assert_eq!(
                Yaml::parse(&emitted).as_ref(),
                Ok(&value),
                "{}: emitted text does not parse back",
                path.display()
            );
        }
        println!("{}: {} files parsed", dir.display(), files.len());
        total += files.len();
    }
    println!("total: {total} YAML files parsed and round-tripped");
}
