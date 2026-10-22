//! The database directory: its file names, its lock, and its durability.
//!
//! # Overview
//!
//! ```text
//!     <path>/
//!         LOCK                   exclusive advisory lock, held while open
//!         00000000.seg           sealed segment
//!         00000000.hint          its index of keys and offsets
//!         00000001.seg           sealed segment
//!         00000001.hint
//!         00000002.seg           active segment, the only one appended to
//!         00000002.hint.tmp      a hint being written; deleted on open
//! ```
//!
//! Identifiers are fixed-width hexadecimal, so lexical order equals numeric order.

use std::{
    fs::{self, File, TryLockError},
    io,
    path::{Path, PathBuf},
};

use crate::Error;

/// Extension of segment files.
const SEGMENT_EXTENSION: &str = "seg";

/// Extension of hint files.
const HINT_EXTENSION: &str = "hint";

/// Extension of files written under a temporary name before an atomic rename.
const TEMPORARY_EXTENSION: &str = "tmp";

/// An open, exclusively locked database directory.
#[derive(Debug)]
pub(crate) struct Directory {
    /// Path of the directory.
    path: PathBuf,
    /// The lock file, whose lock lasts as long as this handle.
    _lock: File,
}

impl Directory {
    /// Creates the directory if needed and takes its exclusive lock.
    ///
    /// The lock is an open-file-description lock, "flock" on Unix.
    /// It conflicts with any other open of the same directory, even from this process.
    /// The kernel releases it when the process dies, so a crash never leaves a stale lock.
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
        fs::create_dir_all(path)?;
        let lock = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path.join("LOCK"))?;
        match lock.try_lock() {
            Ok(()) => Ok(Self {
                path: path.to_path_buf(),
                _lock: lock,
            }),
            Err(TryLockError::WouldBlock) => Err(Error::Locked(path.to_path_buf())),
            Err(TryLockError::Error(err)) => Err(Error::Io(err)),
        }
    }

    /// Returns the path of a segment file.
    pub(crate) fn segment_path(&self, segment: u32) -> PathBuf {
        self.path.join(format!("{segment:08x}.{SEGMENT_EXTENSION}"))
    }

    /// Returns the path of a hint file.
    pub(crate) fn hint_path(&self, segment: u32) -> PathBuf {
        self.path.join(format!("{segment:08x}.{HINT_EXTENSION}"))
    }

    /// Returns the temporary path a hint file is written under.
    pub(crate) fn hint_temporary_path(&self, segment: u32) -> PathBuf {
        self.path.join(format!(
            "{segment:08x}.{HINT_EXTENSION}.{TEMPORARY_EXTENSION}"
        ))
    }

    /// Makes every create, rename and delete in the directory durable.
    ///
    /// On Linux a new file's name is only durable once its directory is synced.
    pub(crate) fn sync(&self) -> io::Result<()> {
        File::open(&self.path)?.sync_all()
    }

    /// Deletes leftovers of interrupted operations and lists the segments in order.
    ///
    /// - Temporary files are hints whose rename never happened.
    /// - Hints without a segment remain from a compaction that deleted the segment first.
    pub(crate) fn clean_and_list(&self) -> io::Result<Vec<u32>> {
        let mut segments = Vec::new();
        let mut hints = Vec::new();
        for entry in fs::read_dir(&self.path)? {
            let path = entry?.path();
            let extension = path.extension().and_then(|ext| ext.to_str());
            // Only fixed-width hexadecimal stems name segments or hints.
            let id = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .filter(|stem| stem.len() == 8)
                .and_then(|stem| u32::from_str_radix(stem, 16).ok());
            match (extension, id) {
                (Some(TEMPORARY_EXTENSION), _) => fs::remove_file(&path)?,
                (Some(SEGMENT_EXTENSION), Some(id)) => segments.push(id),
                (Some(HINT_EXTENSION), Some(id)) => hints.push(id),
                // The lock file and anything foreign are left alone.
                _ => {}
            }
        }
        segments.sort_unstable();
        for hint in hints {
            if segments.binary_search(&hint).is_err() {
                fs::remove_file(self.hint_path(hint))?;
            }
        }
        self.sync()?;
        Ok(segments)
    }
}
