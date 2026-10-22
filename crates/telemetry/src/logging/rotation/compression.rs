//! Compressing the newest rotated file on a background thread.

use std::{
    fs::{self, File},
    io::{self, BufWriter, IntoInnerError},
    path::PathBuf,
    thread::{Builder, JoinHandle},
};

use crate::logging::{
    gzip::GzipWriter,
    rotation::{access::FileAccess, paths::RotationPaths},
};

/// The compression of one rotated file into its gzip form.
///
/// # Invariants
///
/// The gzip form appears under its final name only once complete.
/// An interrupted run leaves the plain file and at most a partial file, never a truncated archive.
#[derive(Debug)]
pub(super) struct Compression {
    /// The plain rotated file, removed once compressed.
    source: PathBuf,

    /// Where the archive is written until it is complete.
    partial: PathBuf,

    /// The archive's final name.
    target: PathBuf,

    /// The access rule the archive is created with.
    access: FileAccess,
}

impl Compression {
    /// The compression of the newest rotated file.
    pub(super) fn newest(paths: &RotationPaths, access: FileAccess) -> Self {
        Self {
            source: paths.rotated(1, false),
            partial: paths.partial(),
            target: paths.rotated(1, true),
            access,
        }
    }

    /// Starts the compression on a thread of its own.
    pub(super) fn spawn(self) -> io::Result<InFlight> {
        let handle = Builder::new()
            .name("log-compression".to_owned())
            .spawn(move || self.run())?;
        Ok(InFlight(handle))
    }

    /// Compresses the file, and removes the partial archive on failure.
    fn run(&self) -> io::Result<()> {
        let result = self.compress();
        if result.is_err() {
            // The plain file is intact; a leftover partial archive would only waste disk.
            let _ = fs::remove_file(&self.partial);
        }
        result
    }

    /// Streams the plain file into the archive, then swaps one for the other.
    fn compress(&self) -> io::Result<()> {
        // Phase 1: stream through bounded buffers, so a file of any size takes little memory.
        let mut source = File::open(&self.source)?;
        let sink = BufWriter::new(self.access.create(&self.partial)?);
        let mut writer = GzipWriter::new(sink)?;
        io::copy(&mut source, &mut writer)?;
        let archive = writer
            .finish()?
            .into_inner()
            .map_err(IntoInnerError::into_error)?;

        // Phase 2: the archive reaches the disk before the plain copy goes.
        // A crash between the two steps then loses no log line.
        archive.sync_all()?;
        fs::rename(&self.partial, &self.target)?;
        fs::remove_file(&self.source)
    }
}

/// A compression still running, which can be waited for.
#[derive(Debug)]
pub(super) struct InFlight(JoinHandle<io::Result<()>>);

impl InFlight {
    /// Waits for the compression to end, and returns its outcome.
    pub(super) fn wait(self) -> io::Result<()> {
        self.0
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("the log compression thread panicked")))
    }
}
