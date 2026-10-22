//! One test case directory, and typed access to its files.

use std::{
    fs,
    path::{Path, PathBuf},
};

use axiom_snappy::raw;
use axiom_ssz::Ssz;
use axiom_types::{ChainConfig, Preset};
use axiom_yaml::Yaml;
use thiserror::Error;

/// Largest decompressed fixture accepted, well above any mainnet state in the vectors.
const MAX_FIXTURE_BYTES: usize = 1 << 30;

/// Why a case failed, with enough context to find the bug.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct Failure(pub String);

impl Failure {
    /// A failure with a message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// The metadata file of a case.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    /// Whether the case must run with signatures checked, ignored, or either.
    pub bls_setting: u64,
    /// Number of blocks in a sanity or finality case.
    pub blocks_count: usize,
}

impl Meta {
    /// Whether the case requires signatures to be ignored.
    ///
    /// The general test format reserves setting 2 for that.
    #[must_use]
    pub const fn bls_ignored(&self) -> bool {
        self.bls_setting == 2
    }
}

/// A test case directory.
#[derive(Clone, Debug)]
pub struct Case {
    /// Path of the case directory.
    path: PathBuf,
}

impl Case {
    /// The case at a directory.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Path of the case directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Name of the case, the last component of its path.
    #[must_use]
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Whether a file exists in the case.
    #[must_use]
    pub fn has(&self, file: &str) -> bool {
        self.path.join(file).exists()
    }

    /// Decodes a snappy-compressed SSZ file.
    ///
    /// # Errors
    ///
    /// Fails when the file is missing, does not decompress, or does not decode.
    pub fn ssz<T: Ssz>(&self, stem: &str) -> Result<T, Failure> {
        let bytes = self.ssz_bytes(stem)?;
        T::decode(&bytes).map_err(|error| Failure(format!("{stem}: SSZ decode failed: {error}")))
    }

    /// Decodes a snappy-compressed SSZ file, or nothing when it is absent.
    ///
    /// # Errors
    ///
    /// Fails when the file exists but does not decode.
    pub fn ssz_if_present<T: Ssz>(&self, stem: &str) -> Result<Option<T>, Failure> {
        if self.has(&format!("{stem}.ssz_snappy")) {
            self.ssz(stem).map(Some)
        } else {
            Ok(None)
        }
    }

    /// The raw bytes of a snappy-compressed SSZ file.
    ///
    /// # Errors
    ///
    /// Fails when the file is missing or does not decompress.
    pub fn ssz_bytes(&self, stem: &str) -> Result<Vec<u8>, Failure> {
        let path = self.path.join(format!("{stem}.ssz_snappy"));
        let compressed =
            fs::read(&path).map_err(|error| Failure(format!("{}: {error}", path.display())))?;
        raw::decompress(&compressed, MAX_FIXTURE_BYTES)
            .map_err(|error| Failure(format!("{stem}: snappy failed: {error}")))
    }

    /// Parses a YAML file.
    ///
    /// # Errors
    ///
    /// Fails when the file is missing or does not parse.
    pub fn yaml(&self, file: &str) -> Result<Yaml, Failure> {
        let path = self.path.join(file);
        let text = fs::read_to_string(&path)
            .map_err(|error| Failure(format!("{}: {error}", path.display())))?;
        Yaml::parse(&text).map_err(|error| Failure(format!("{file}: {error}")))
    }

    /// The configuration of the case: its own file when it ships one, the preset's otherwise.
    ///
    /// # Errors
    ///
    /// Fails when the case's configuration file does not parse.
    pub fn config<P: Preset>(&self) -> Result<ChainConfig, Failure> {
        if !self.has("config.yaml") {
            return Ok(ChainConfig::for_preset::<P>().with_forks_at_genesis());
        }
        ChainConfig::from_yaml(&self.yaml("config.yaml")?)
            .map_err(|error| Failure(format!("config.yaml: {error}")))
    }

    /// The case metadata, with defaults when the file is absent.
    ///
    /// # Errors
    ///
    /// Fails when the file exists but does not parse.
    pub fn meta(&self) -> Result<Meta, Failure> {
        if !self.has("meta.yaml") {
            return Ok(Meta::default());
        }
        let yaml = self.yaml("meta.yaml")?;
        let field = |key: &str| yaml.get(key).and_then(Yaml::as_u64).unwrap_or(0);
        Ok(Meta {
            bls_setting: field("bls_setting"),
            blocks_count: field("blocks_count") as usize,
        })
    }
}
