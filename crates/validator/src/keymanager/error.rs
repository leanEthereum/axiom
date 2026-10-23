//! Why the key directory could not be read or written.

use std::{io, path::PathBuf};

use axiom_http::HttpError;
use axiom_types::BlsPubkey;
use axiom_yaml::ParseError;
use thiserror::Error;

use crate::{keys::KeystoreError, validators::FieldError};

/// Why the key directory could not be read or written.
#[derive(Debug, Error)]
pub enum DirectoryError {
    /// A file could not be read or written.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// What the operating system said.
        #[source]
        source: io::Error,
    },
    /// A keystore file is not a valid EIP-2335 keystore.
    #[error("keystore {}: {source}", path.display())]
    Keystore {
        /// The keystore file.
        path: PathBuf,
        /// What is wrong with it.
        #[source]
        source: Box<KeystoreError>,
    },
    /// A keystore file is named after another key than the one it holds.
    #[error("keystore {} holds key {actual}, not the key its name gives", path.display())]
    Misnamed {
        /// The keystore file.
        path: PathBuf,
        /// The key the keystore holds.
        actual: String,
    },
    /// A keystore did not open with its stored password.
    #[error("keystore {}: {source}", path.display())]
    Unlock {
        /// The keystore file.
        path: PathBuf,
        /// Why it did not open.
        #[source]
        source: Box<KeystoreError>,
    },
    /// The validator definitions file is malformed.
    #[error("validator definitions {}: {source}", path.display())]
    Definitions {
        /// The definitions file.
        path: PathBuf,
        /// What is wrong with it.
        #[source]
        source: DefinitionsError,
    },
    /// An enabled local key has no keystore in the directory.
    #[error("validator {pubkey} is defined, but {} does not exist", path.display())]
    MissingKeystore {
        /// The key.
        pubkey: BlsPubkey,
        /// Where its keystore should be.
        path: PathBuf,
    },
    /// A remote signer URL is not an http or https URL.
    #[error("remote signer URL {url:?}: {source}")]
    Url {
        /// The URL as stored.
        url: String,
        /// Why it does not parse.
        #[source]
        source: HttpError,
    },
}

/// Why the definitions file cannot be read.
#[derive(Debug, Error)]
pub enum DefinitionsError {
    /// The text is not YAML of the supported subset.
    #[error("{0}")]
    Text(#[source] ParseError),
    /// The document is not a sequence of definitions.
    #[error("the document is not a sequence of definitions")]
    NotASequence,
    /// An entry is malformed.
    #[error("entry {index}: {source}")]
    Entry {
        /// The entry's position, counting from zero.
        index: usize,
        /// What is wrong with it.
        #[source]
        source: FieldError,
    },
    /// Two entries name one key.
    #[error("entry {index} defines validator {pubkey} again")]
    Duplicate {
        /// The later entry's position.
        index: usize,
        /// The key.
        pubkey: BlsPubkey,
    },
}
