//! Why the key directory could not be read or written.

use std::{io, path::PathBuf};

use axiom_http::HttpError;
use axiom_json::ParseError;
use thiserror::Error;

use crate::{json::JsonError, keys::KeystoreError, signing::LocalKeyError};

/// Why a keystore did not open.
#[derive(Debug, Error)]
pub enum UnlockError {
    /// The password is wrong, or the decrypted secret does not match the stored public key.
    #[error("keystore: {0}")]
    Keystore(#[from] KeystoreError),
    /// The decrypted secret cannot sign as a local key.
    #[error("local key: {0}")]
    Key(#[from] LocalKeyError),
}

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
        source: Box<UnlockError>,
    },
    /// The remote key list is not JSON.
    #[error("remote keys {}: {source}", path.display())]
    RemoteText {
        /// The remote key list.
        path: PathBuf,
        /// Where the text stops being JSON.
        #[source]
        source: ParseError,
    },
    /// The remote key list is JSON of the wrong shape.
    #[error("remote keys {}: {source}", path.display())]
    RemoteShape {
        /// The remote key list.
        path: PathBuf,
        /// What is wrong with its shape.
        #[source]
        source: JsonError,
    },
    /// A remote signer URL is not a plain http URL.
    #[error("remote signer URL {url:?}: {source}")]
    Url {
        /// The URL as stored.
        url: String,
        /// Why it does not parse.
        #[source]
        source: HttpError,
    },
}
