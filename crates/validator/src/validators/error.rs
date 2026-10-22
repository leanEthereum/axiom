//! Why a proposal setting could not be read.

use std::{io, path::PathBuf};

use axiom_beacon_json::ApiJsonError;
use thiserror::Error;

/// Why text cannot be a block's graffiti.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum GraffitiError {
    /// The text is longer than the block's field.
    #[error("graffiti of {len} bytes exceeds the {max} a block holds")]
    TooLong {
        /// Bytes of the text.
        len: usize,
        /// Bytes the field holds.
        max: usize,
    },
}

/// Why a graffiti file could not be read.
#[derive(Debug, Error)]
pub enum GraffitiFileError {
    /// The file could not be read.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// What the operating system said.
        #[source]
        source: io::Error,
    },
    /// A line is not a key, a colon, and graffiti.
    #[error("{} line {line}: {reason}", path.display())]
    Line {
        /// The file.
        path: PathBuf,
        /// The line, counting from one.
        line: usize,
        /// What is wrong with it.
        reason: String,
    },
}

/// Why a field of a hand-editable file cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("field {field}: expected {expected}")]
pub struct FieldError {
    /// The field.
    pub field: &'static str,
    /// What the field must hold.
    pub expected: &'static str,
}

impl FieldError {
    /// A field that does not hold what it must.
    #[must_use]
    pub const fn new(field: &'static str, expected: &'static str) -> Self {
        Self { field, expected }
    }
}

/// Why a builder configuration is refused.
///
/// See `types/builder_entry.yaml` in the keymanager API repository.
#[derive(Debug, Error)]
pub enum BuilderConfigError {
    /// The configuration is JSON of the wrong shape.
    #[error("{0}")]
    Json(#[from] ApiJsonError),
    /// The builders member is not an array.
    #[error("builders is not an array")]
    BuildersShape,
    /// More builders than a configuration holds.
    #[error("{count} builders exceed the limit of {max}")]
    TooManyBuilders {
        /// Builders given.
        count: usize,
        /// The most allowed.
        max: usize,
    },
    /// A builder's URL is not an http or https URL with a host.
    #[error("builder {index}: {url:?} is not an http or https URL with a host")]
    Url {
        /// The builder's position.
        index: usize,
        /// The URL given.
        url: String,
    },
    /// A builder's URL is longer than allowed.
    #[error("builder {index}: URL of {len} bytes exceeds the limit of {max}")]
    UrlTooLong {
        /// The builder's position.
        index: usize,
        /// Bytes of the URL.
        len: usize,
        /// The most allowed.
        max: usize,
    },
    /// A builder's authentication data is not hex.
    #[error("builder {index}: auth_data {text:?} is not 0x-prefixed hex")]
    AuthDataHex {
        /// The builder's position.
        index: usize,
        /// The text given.
        text: String,
    },
    /// A builder's authentication data is empty or too long.
    #[error("builder {index}: auth_data of {len} bytes is outside 1 to {max}")]
    AuthDataLength {
        /// The builder's position.
        index: usize,
        /// Bytes given.
        len: usize,
        /// The most allowed.
        max: usize,
    },
    /// A builder lists more keys than allowed.
    #[error("builder {index}: {count} builder public keys exceed the limit of {max}")]
    TooManyBuilderPubkeys {
        /// The builder's position.
        index: usize,
        /// Keys given.
        count: usize,
        /// The most allowed.
        max: usize,
    },
    /// Two builders share both their URL and their authentication data.
    #[error("builders {first} and {second} share URL {url:?} and auth_data")]
    Duplicate {
        /// The earlier builder's position.
        first: usize,
        /// The later builder's position.
        second: usize,
        /// The shared URL.
        url: String,
    },
}
