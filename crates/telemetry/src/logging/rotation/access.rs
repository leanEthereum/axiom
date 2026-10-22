//! Who may read the log files, applied when each file is opened.

#[cfg(unix)]
use std::{
    fs::Permissions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};
use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
};

/// The access rule every log file is opened with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileAccess {
    /// Whether only the owner may read the files.
    restricted: bool,
}

impl FileAccess {
    /// The rule for owner-only or world-readable files.
    pub(super) const fn new(restricted: bool) -> Self {
        Self { restricted }
    }

    /// Opens a file for appending, creating it when missing.
    pub(super) fn append(self, path: &Path) -> io::Result<File> {
        self.open(path, OpenOptions::new().append(true).create(true))
    }

    /// Creates a file, emptying any file already there.
    pub(super) fn create(self, path: &Path) -> io::Result<File> {
        self.open(
            path,
            OpenOptions::new().write(true).create(true).truncate(true),
        )
    }

    /// Opens a file and gives it this rule's permissions.
    fn open(self, path: &Path, options: &mut OpenOptions) -> io::Result<File> {
        #[cfg(unix)]
        {
            // Why: the creation mode leaves no moment where a new file is too open.
            // The explicit change then overrides the umask, and fixes an older file.
            let mode = if self.restricted { 0o600 } else { 0o644 };
            let file = options.mode(mode).open(path)?;
            file.set_permissions(Permissions::from_mode(mode))?;
            Ok(file)
        }
        #[cfg(not(unix))]
        {
            // Other platforms have no mode bits; the file inherits its directory's access rules.
            let _ = self.restricted;
            options.open(path)
        }
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::{env, fs, process};

    use super::*;

    /// The permission bits of a fresh file opened under a rule.
    fn mode(restricted: bool) -> u32 {
        let path = env::temp_dir().join(format!("axiom-log-access-{restricted}-{}", process::id()));
        drop(FileAccess::new(restricted).create(&path).unwrap());
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        fs::remove_file(&path).unwrap();
        mode
    }

    #[test]
    fn restricted_files_are_owner_only() {
        // Read and write for the owner, nothing for anyone else.
        assert_eq!(mode(true), 0o600);
    }

    #[test]
    fn unrestricted_files_are_world_readable() {
        // Read and write for the owner, read for group and others, whatever the umask.
        assert_eq!(mode(false), 0o644);
    }
}
