//! Locating the downloaded vector sets and decoding the hex they are written in.

use std::{
    env,
    path::{Path, PathBuf},
};

/// The root of one downloaded vector set.
///
/// The root is AXIOM_VECTORS when set, else the workspace's testing/vectors.
/// A missing set skips its suites, unless AXIOM_REQUIRE_VECTORS is set, as CI does.
#[derive(Debug)]
pub(crate) struct Vectors {
    /// The directory of the set.
    root: PathBuf,
}

impl Vectors {
    /// The set under the given directory of the vectors root, or none when it is absent.
    ///
    /// # Panics
    ///
    /// Panics when the set is absent and AXIOM_REQUIRE_VECTORS is set.
    #[expect(
        clippy::print_stderr,
        reason = "a skipped suite says why in the test output"
    )]
    pub(crate) fn locate(set: &str) -> Option<Self> {
        // The variable wins, so a worktree can point at a shared checkout.
        let root = env::var_os("AXIOM_VECTORS")
            .map_or_else(
                || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors"),
                PathBuf::from,
            )
            .join(set);
        let found = root.is_dir();
        assert!(
            found || env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
            "vectors required but missing under {}; run make -C testing/ef-tests",
            root.display()
        );
        if !found {
            eprintln!("skipping: {} not found (set AXIOM_VECTORS)", root.display());
        }
        found.then_some(Self { root })
    }

    /// The path of a file of the set.
    pub(crate) fn path(&self, file: &str) -> PathBuf {
        self.root.join(file)
    }
}

/// Decodes hex without a prefix, none on an odd length or a non-hex digit.
pub(crate) fn hex(text: &str) -> Option<Vec<u8>> {
    // Two digits per byte, most significant first.
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}
