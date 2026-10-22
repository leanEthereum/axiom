//! The active log file, rotated by size.

use std::{
    fs::{self, File},
    io::{self, Write},
};

use crate::logging::{
    LogError, LogFile,
    rotation::{
        access::FileAccess,
        compression::{Compression, InFlight},
        paths::RotationPaths,
    },
};

/// An append-only log file that rotates once it reaches its size cap.
///
/// # Invariants
///
/// The stored files never outnumber the configured count, the active one included.
///
/// A rotation first waits for the previous compression to end.
/// No shift then moves a file a compression is still reading or writing.
/// The wait blocks only when a whole file fills faster than one compresses.
#[derive(Debug)]
pub(crate) struct RotatingFile {
    /// The names of the active and rotated files.
    paths: RotationPaths,

    /// The access rule of every file.
    access: FileAccess,

    /// The size cap of the active file, in bytes.
    max_size: u64,

    /// How many rotated files are kept, one fewer than the configured count.
    kept: usize,

    /// Whether rotated files are compressed.
    compress: bool,

    /// The active file.
    file: File,

    /// The bytes in the active file.
    size: u64,

    /// The compression started by the last rotation, if not yet waited for.
    compression: Option<InFlight>,
}

impl RotatingFile {
    /// Opens the active file for appending, creating it and its directory when missing.
    pub(crate) fn open(config: &LogFile) -> Result<Self, LogError> {
        fs::create_dir_all(&config.directory)
            .map_err(|error| LogError::cannot_open(&config.directory, &error))?;
        let paths = RotationPaths::new(&config.directory, &config.name);
        let access = FileAccess::new(config.restricted);
        let file = access
            .append(paths.active())
            .map_err(|error| LogError::cannot_open(paths.active(), &error))?;
        // A restart resumes the file, so the bytes already there count toward the cap.
        let size = file
            .metadata()
            .map_err(|error| LogError::cannot_open(paths.active(), &error))?
            .len();
        // A partial archive is what a process stopped mid-compression leaves.
        // Its plain source is still there and rotates as an uncompressed file.
        let _ = fs::remove_file(paths.partial());
        Ok(Self {
            paths,
            access,
            max_size: config.max_size.get(),
            kept: config.max_files.get() - 1,
            compress: config.compress,
            file,
            size,
            compression: None,
        })
    }

    /// Moves the active file to the first rotated place and opens a fresh one.
    fn rotate(&mut self) -> io::Result<()> {
        // Phase 1: the previous compression ends, so no file moves under it.
        // A failed compression leaves its plain file, which rotates like any other.
        let _ = self.settle();

        // Phase 2: drop the oldest file, then move each one place older, oldest first.
        if self.kept > 0 {
            self.paths.discard(self.kept)?;
            for index in (1..self.kept).rev() {
                self.paths.shift(index)?;
            }
            fs::rename(self.paths.active(), self.paths.rotated(1, false))?;
        }

        // Phase 3: a fresh active file.
        // With no rotated file kept, this empties the active file in place.
        self.file = self.access.create(self.paths.active())?;
        self.size = 0;

        // Phase 4: compress the file just rotated, off the logging path.
        // A thread that cannot start leaves the file plain, so the log line still lands.
        if self.compress && self.kept > 0 {
            self.compression = Compression::newest(&self.paths, self.access).spawn().ok();
        }
        Ok(())
    }

    /// Waits for the last compression to end, and returns its outcome.
    pub(super) fn settle(&mut self) -> io::Result<()> {
        match self.compression.take() {
            Some(compression) => compression.wait(),
            None => Ok(()),
        }
    }
}

impl Write for RotatingFile {
    fn write(&mut self, line: &[u8]) -> io::Result<usize> {
        let length = line.len() as u64;
        // Threshold: rotate when this line would carry the file past its cap.
        // An empty file takes any line, so a line longer than the cap cannot rotate forever.
        if self.size > 0 && self.size + length > self.max_size {
            self.rotate()?;
        }
        // The whole line goes to one file, so no line is split across a rotation.
        self.file.write_all(line)?;
        self.size += length;
        Ok(line.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        num::{NonZeroU64, NonZeroUsize},
        path::PathBuf,
        process,
    };

    use super::*;
    use crate::logging::gzip::gunzip;

    /// A fresh directory, removed when the test ends.
    struct Scratch(PathBuf);

    impl Scratch {
        /// An empty directory named after the test.
        fn new(test: &str) -> Self {
            let path = env::temp_dir().join(format!("axiom-log-{test}-{}", process::id()));
            // A directory left by an interrupted run would leak its files into this one.
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }

        /// A log named beacon in this directory, with a size cap and a file count.
        fn log(&self, max_size: u64, max_files: usize) -> LogFile {
            LogFile {
                max_size: NonZeroU64::new(max_size).unwrap(),
                max_files: NonZeroUsize::new(max_files).unwrap(),
                ..LogFile::new(self.0.clone(), "beacon".to_owned())
            }
        }

        /// Every file name with its text, archives decompressed, in name order.
        fn files(&self) -> Vec<(String, String)> {
            let mut files: Vec<(String, String)> = fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let name = path.file_name().unwrap().to_str().unwrap().to_owned();
                    let mut bytes = fs::read(&path).unwrap();
                    if path.extension().is_some_and(|extension| extension == "gz") {
                        bytes = gunzip(&bytes);
                    }
                    (name, String::from_utf8(bytes).unwrap())
                })
                .collect();
            files.sort();
            files
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Writes each line as one log event.
    fn write_lines(file: &mut RotatingFile, lines: &[&str]) {
        for line in lines {
            file.write_all(line.as_bytes()).unwrap();
        }
    }

    /// A list of file names and texts, for comparison.
    fn expected(files: &[(&str, &str)]) -> Vec<(String, String)> {
        files
            .iter()
            .map(|&(name, text)| (name.to_owned(), text.to_owned()))
            .collect()
    }

    #[test]
    fn rotates_only_past_the_exact_cap() {
        // Threshold: a 12-byte cap and 4-byte lines.
        let scratch = Scratch::new("boundary");
        let mut file = RotatingFile::open(&scratch.log(12, 3)).unwrap();

        // Three lines fill the file to exactly 12 bytes, which is still within the cap.
        write_lines(&mut file, &["aaa\n", "bbb\n", "ccc\n"]);
        assert_eq!(
            scratch.files(),
            expected(&[("beacon.log", "aaa\nbbb\nccc\n")])
        );

        // A fourth would make 16, so the full file rotates first.
        write_lines(&mut file, &["ddd\n"]);
        assert_eq!(
            scratch.files(),
            expected(&[("beacon.log", "ddd\n"), ("beacon.log.1", "aaa\nbbb\nccc\n")])
        );
    }

    #[test]
    fn the_count_includes_the_active_file() {
        // A 4-byte cap makes every 4-byte line after the first rotate.
        // Six lines, so five rotations, with at most three files kept.
        let scratch = Scratch::new("count");
        let mut file = RotatingFile::open(&scratch.log(4, 3)).unwrap();
        write_lines(
            &mut file,
            &["000\n", "111\n", "222\n", "333\n", "444\n", "555\n"],
        );

        // The three newest lines survive, the newest in the active file.
        assert_eq!(
            scratch.files(),
            expected(&[
                ("beacon.log", "555\n"),
                ("beacon.log.1", "444\n"),
                ("beacon.log.2", "333\n"),
            ])
        );
    }

    #[test]
    fn a_single_file_empties_in_place() {
        // A count of one keeps no rotated file at all.
        let scratch = Scratch::new("single");
        let mut file = RotatingFile::open(&scratch.log(4, 1)).unwrap();
        write_lines(&mut file, &["000\n", "111\n"]);

        // The second line replaced the first.
        assert_eq!(scratch.files(), expected(&[("beacon.log", "111\n")]));
    }

    #[test]
    fn a_line_longer_than_the_cap_still_lands() {
        // A 4-byte cap and a 9-byte line.
        let scratch = Scratch::new("oversized");
        let mut file = RotatingFile::open(&scratch.log(4, 3)).unwrap();

        // The empty file takes it whole, without rotating.
        write_lines(&mut file, &["too long\n"]);
        assert_eq!(scratch.files(), expected(&[("beacon.log", "too long\n")]));

        // The next line rotates it out like any full file.
        write_lines(&mut file, &["ok\n"]);
        assert_eq!(
            scratch.files(),
            expected(&[("beacon.log", "ok\n"), ("beacon.log.1", "too long\n")])
        );
    }

    #[test]
    fn a_restart_appends_and_counts_the_existing_bytes() {
        // Fixture state: an 8-byte active file from an earlier run, and a 10-byte cap.
        let scratch = Scratch::new("resume");
        fs::create_dir_all(&scratch.0).unwrap();
        fs::write(scratch.0.join("beacon.log"), "earlier\n").unwrap();
        let mut file = RotatingFile::open(&scratch.log(10, 3)).unwrap();

        // 8 + 2 = 10 bytes fits, so the line is appended to the old text.
        write_lines(&mut file, &["x\n"]);
        assert_eq!(scratch.files(), expected(&[("beacon.log", "earlier\nx\n")]));

        // 10 + 2 = 12 bytes does not, so the resumed file rotates.
        write_lines(&mut file, &["y\n"]);
        assert_eq!(
            scratch.files(),
            expected(&[("beacon.log", "y\n"), ("beacon.log.1", "earlier\nx\n")])
        );
    }

    #[test]
    fn compressed_files_shift_as_archives() {
        // A 4-byte cap, three files, and compression.
        let scratch = Scratch::new("compressed");
        let log = LogFile {
            compress: true,
            ..scratch.log(4, 3)
        };
        let mut file = RotatingFile::open(&log).unwrap();

        // Three lines, two rotations; the second waits for the first archive.
        write_lines(&mut file, &["000\n", "111\n", "222\n"]);
        file.settle().unwrap();

        // Each archive inflates back to its line, and no plain copy or partial file is left.
        assert_eq!(
            scratch.files(),
            expected(&[
                ("beacon.log", "222\n"),
                ("beacon.log.1.gz", "111\n"),
                ("beacon.log.2.gz", "000\n"),
            ])
        );
    }

    #[test]
    fn an_unusable_directory_is_reported() {
        // Fixture state: the configured directory is a regular file.
        let scratch = Scratch::new("unusable");
        fs::create_dir_all(&scratch.0).unwrap();
        let directory = scratch.0.join("not-a-directory");
        fs::write(&directory, "").unwrap();
        let log = LogFile::new(directory.clone(), "beacon".to_owned());

        // The error names the directory and carries the system's own reason.
        let reason = fs::create_dir_all(&directory).unwrap_err().to_string();
        assert_eq!(
            RotatingFile::open(&log).unwrap_err(),
            LogError::CannotOpen {
                path: directory,
                reason
            }
        );
    }
}
