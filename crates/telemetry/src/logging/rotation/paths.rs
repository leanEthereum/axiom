//! The names of the active and rotated log files, and moving files between them.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// The file names of one rotating log.
///
/// ```text
///     beacon.log          the active file
///     beacon.log.1        the newest rotated file
///     beacon.log.2.gz     an older rotated file, compressed
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RotationPaths {
    /// The active file, whose path prefixes every other.
    active: PathBuf,
}

impl RotationPaths {
    /// The names of a log in a directory.
    pub(super) fn new(directory: &Path, name: &str) -> Self {
        Self {
            active: directory.join(format!("{name}.log")),
        }
    }

    /// The file being written.
    pub(super) fn active(&self) -> &Path {
        &self.active
    }

    /// The rotated file at an index, counted from one for the newest.
    pub(super) fn rotated(&self, index: usize, compressed: bool) -> PathBuf {
        let suffix = if compressed { ".gz" } else { "" };
        self.suffixed(&format!(".{index}{suffix}"))
    }

    /// The temporary file a compression writes before it is complete.
    pub(super) fn partial(&self) -> PathBuf {
        self.suffixed(".1.gz.partial")
    }

    /// Deletes the rotated file at an index, in either form.
    pub(super) fn discard(&self, index: usize) -> io::Result<()> {
        for compressed in [false, true] {
            Self::missing_is_fine(fs::remove_file(self.rotated(index, compressed)))?;
        }
        Ok(())
    }

    /// Moves the rotated file at an index one place older, keeping its form.
    pub(super) fn shift(&self, index: usize) -> io::Result<()> {
        for compressed in [false, true] {
            let from = self.rotated(index, compressed);
            let to = self.rotated(index + 1, compressed);
            Self::missing_is_fine(fs::rename(from, to))?;
        }
        Ok(())
    }

    /// Treats an absent file as already handled.
    ///
    /// Each index holds one form, so the other form is routinely absent.
    fn missing_is_fine(result: io::Result<()>) -> io::Result<()> {
        match result {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    /// The active path with a suffix appended.
    fn suffixed(&self, suffix: &str) -> PathBuf {
        let mut path = self.active.clone().into_os_string();
        path.push(suffix);
        path.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_extend_the_active_file() {
        // The three shapes of name, for the log "beacon" in "/var/log/axiom".
        let paths = RotationPaths::new(Path::new("/var/log/axiom"), "beacon");
        assert_eq!(paths.active(), Path::new("/var/log/axiom/beacon.log"));
        assert_eq!(
            paths.rotated(3, false),
            Path::new("/var/log/axiom/beacon.log.3")
        );
        assert_eq!(
            paths.rotated(3, true),
            Path::new("/var/log/axiom/beacon.log.3.gz")
        );
        assert_eq!(
            paths.partial(),
            Path::new("/var/log/axiom/beacon.log.1.gz.partial")
        );
    }
}
