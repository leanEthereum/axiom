//! Where and how a copy of the log is kept on disk.

use std::{
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    sync::Mutex,
};

use tracing::level_filters::LevelFilter;

use crate::logging::{LogError, LogFormat, format::BoxedLayer, rotation::RotatingFile};

/// A size-capped, rotating set of log files in one directory.
///
/// The active file is the name with a log suffix, and rotated files add an index.
/// A zero size or count cannot be expressed: the caller then configures no file at all.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LogFile {
    /// The directory holding every file, created when missing.
    pub directory: PathBuf,

    /// The file name before its suffixes, such as the process role.
    pub name: String,

    /// The most verbose level written to the file.
    pub level: LevelFilter,

    /// The layout of each line.
    pub format: LogFormat,

    /// The largest size in bytes the active file reaches before it rotates.
    pub max_size: NonZeroU64,

    /// The most files kept, the active one included.
    pub max_files: NonZeroUsize,

    /// Whether rotated files are gzip-compressed in the background.
    pub compress: bool,

    /// Whether only the owner may read the files.
    ///
    /// On unix, files get mode 0600 when set and 0644 otherwise.
    /// Other platforms keep their default access rules.
    pub restricted: bool,

    /// Whether lines keep their terminal colour escape codes.
    pub color: bool,
}

impl LogFile {
    /// The default size cap, small enough for an editor to open one file.
    ///
    /// With the default count, the files together stay under two gigabytes.
    pub const DEFAULT_MAX_SIZE: NonZeroU64 =
        NonZeroU64::new(200 << 20).expect("200 MiB is not zero");

    /// The default count, bounding the disk the files use together.
    pub const DEFAULT_MAX_FILES: NonZeroUsize = NonZeroUsize::new(10).expect("10 is not zero");

    /// A file in a directory, with the default limits.
    ///
    /// Files keep debug detail, readable by the owner only, uncompressed and uncoloured.
    #[must_use]
    pub fn new(directory: PathBuf, name: String) -> Self {
        Self {
            directory,
            name,
            // A file is read after the fact, so it keeps more detail than the terminal.
            level: LevelFilter::DEBUG,
            format: LogFormat::default(),
            max_size: Self::DEFAULT_MAX_SIZE,
            max_files: Self::DEFAULT_MAX_FILES,
            compress: false,
            // Logs name peers and validators, so other local users get no read access.
            restricted: true,
            color: false,
        }
    }

    /// Opens the file and returns the output writing to it.
    ///
    /// # Errors
    ///
    /// Fails when the directory or the active file cannot be opened.
    pub(crate) fn layer(&self) -> Result<BoxedLayer, LogError> {
        let file = RotatingFile::open(self)?;
        // The lock serializes whole lines; the file never panics while holding it.
        Ok(self.format.layer(Mutex::new(file), self.color, self.level))
    }
}
