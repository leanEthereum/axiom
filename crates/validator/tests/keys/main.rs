//! Conformance of the validator key stack against published vector files.
//!
//! The files live outside the repository and come from make -C testing/ef-tests.
//! Point AXIOM_VECTORS at the vectors root, which defaults to the workspace's testing/vectors.

mod bip39;
mod unicode;

use std::{
    env,
    path::{Path, PathBuf},
};

/// A file under the vectors root, or none when it is absent.
///
/// When AXIOM_REQUIRE_VECTORS is set, a missing file fails the run instead.
#[expect(
    clippy::print_stderr,
    reason = "a skipped suite says why in the test output"
)]
fn vector_file(relative: &str) -> Option<PathBuf> {
    let root = env::var_os("AXIOM_VECTORS").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors"),
        PathBuf::from,
    );
    let file = root.join(relative);
    let found = file.is_file();
    assert!(
        found || env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
        "vectors required but missing at {}; run make -C testing/ef-tests",
        file.display()
    );
    if !found {
        eprintln!("skipping: {} not found (set AXIOM_VECTORS)", file.display());
    }
    found.then_some(file)
}
