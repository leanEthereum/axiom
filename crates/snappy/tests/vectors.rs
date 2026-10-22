//! Decodes every SSZ-snappy file of the consensus spec tests, then round-trips it.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use axiom_snappy::raw;

/// SSZ-snappy files in the consensus spec tests at the release pinned in testing/ef-tests/Makefile.
///
/// A shrinking download or a listing bug changes this count and fails the suite.
const SSZ_SNAPPY_FILES: usize = 246_238;

/// Directory of the downloaded consensus spec tests, if present.
///
/// The `AXIOM_VECTORS` variable wins.
/// Otherwise the nearest ancestor holding `testing/vectors` is used.
/// Vectors are gitignored, so a git worktree finds them in the main checkout above it.
///
/// # Panics
///
/// Panics when the vectors are missing and `AXIOM_REQUIRE_VECTORS` is set, as in CI.
fn vectors_dir() -> Option<PathBuf> {
    let root = env::var_os("AXIOM_VECTORS").map(PathBuf::from).or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .map(|dir| dir.join("testing/vectors"))
            .find(|dir| dir.join("consensus-spec-tests").is_dir())
    });
    let dir = root.map(|root| root.join("consensus-spec-tests/tests"));
    let found = dir.as_ref().is_some_and(|dir| dir.is_dir());
    assert!(
        found || env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
        "consensus spec tests required but missing; run `make -C testing/ef-tests`"
    );
    dir.filter(|_| found)
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
fn decodes_and_round_trips_every_ssz_snappy_vector() {
    let Some(root) = vectors_dir() else {
        println!("skipped: no testing/vectors found; set AXIOM_VECTORS to run the corpus");
        return;
    };
    let files = files_with_extension(&root, "ssz_snappy");
    assert_eq!(files.len(), SSZ_SNAPPY_FILES, "ssz_snappy file count");

    let mut identical = 0_usize;
    let mut reference_bytes = 0_usize;
    let mut our_bytes = 0_usize;
    let mut raw_bytes = 0_usize;
    for path in &files {
        let compressed = fs::read(path).expect("vector file is readable");

        // The vectors use the raw block format; the preamble gives the exact bound.
        let len = raw::decompressed_len(&compressed).expect("vector has a preamble");
        let data = raw::decompress(&compressed, len)
            .unwrap_or_else(|err| panic!("{}: {err}", path.display()));

        // Law: our compression decodes back to the same bytes.
        let ours = raw::compress(&data);
        assert_eq!(
            raw::decompress(&ours, len).as_ref(),
            Ok(&data),
            "{}",
            path.display()
        );

        // Statistics: how often the output is byte-identical to the reference compressor.
        identical += usize::from(ours == compressed);
        reference_bytes += compressed.len();
        our_bytes += ours.len();
        raw_bytes += data.len();
    }

    println!("{} ssz_snappy files decoded and round-tripped", files.len());
    println!("{identical} re-compress byte-identical to the reference output");
    println!("uncompressed {raw_bytes} B, reference {reference_bytes} B, ours {our_bytes} B");
}
