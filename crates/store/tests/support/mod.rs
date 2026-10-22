//! Fixtures shared by the integration tests.

#![allow(
    dead_code,
    reason = "each test binary uses a different subset of the fixtures"
)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use axiom_store::{Options, SyncPolicy};

/// A fresh directory under the system temporary directory, deleted on drop.
#[derive(Debug)]
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    /// Creates a directory name unique to this process and call, in the system temporary directory.
    pub(crate) fn new(label: &str) -> Self {
        Self::under(&env::temp_dir(), label)
    }

    /// Creates a unique directory under the build directory, which sits on a real disk.
    ///
    /// The system temporary directory is often a RAM filesystem, where a sync costs nothing.
    pub(crate) fn on_disk(label: &str) -> Self {
        Self::under(Path::new(env!("CARGO_TARGET_TMPDIR")), label)
    }

    /// Creates a unique directory name under a parent.
    fn under(parent: &Path, label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("axiom-store-{label}-{}-{id}", process::id()));
        // A leftover from a killed earlier run would otherwise leak into this test.
        fs::remove_dir_all(&path).ok();
        Self(path)
    }

    /// Returns the path.
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

/// Options with tiny segments and manual compaction, to exercise rotation in small tests.
pub(crate) const fn small_segments() -> Options {
    Options {
        sync: SyncPolicy::Manual,
        segment_size: 256,
        compaction_threshold: 50,
        auto_compact: false,
    }
}

/// Lists the segment files of a store directory, oldest first.
pub(crate) fn segment_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .expect("store directory is listable")
        .map(|entry| entry.expect("directory entry is readable").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "seg"))
        .collect();
    files.sort();
    files
}
