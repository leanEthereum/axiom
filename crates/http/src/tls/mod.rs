//! HTTPS: TLS under the client and the server, from the platform's roots and PEM files.
//!
//! # Overview
//!
//! The TLS crate is pure, so this module supplies what it cannot read itself:
//!
//! - the roots, from the platform bundle and any extra PEM files;
//! - the server's certificate chain and key, from PEM files;
//! - fresh randomness for each handshake, from the operating system;
//! - the current time, for certificate validity.
//!
//! A client speaks TLS 1.3 or TLS 1.2, as the server chooses; a server speaks TLS 1.3.

mod roots;
mod stream;

use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axiom_tls::{CertifiedKey, KeyError, PemError, Randomness};
pub use roots::TrustRoots;
pub(crate) use stream::TlsStream;
use thiserror::Error;

/// Path of the kernel's non-blocking entropy device.
const ENTROPY_DEVICE: &str = "/dev/urandom";

/// A TLS root store or identity that cannot be loaded.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TlsSetupError {
    /// A file cannot be read.
    #[error("cannot read {path}: {reason}")]
    Read {
        /// The file.
        path: PathBuf,
        /// The operating system's reason.
        reason: String,
    },

    /// A file is not PEM.
    #[error("{path} is not PEM: {source}")]
    Pem {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        #[source]
        source: PemError,
    },

    /// A file named as a root holds no usable certificate.
    #[error("{path} holds no usable certificate")]
    NoCertificate {
        /// The file.
        path: PathBuf,
    },

    /// No platform bundle holds a usable root.
    #[error("no trusted roots found; set SSL_CERT_FILE to a PEM bundle")]
    NoRoots,

    /// A certificate chain or private key cannot serve as the server's identity.
    #[error("invalid TLS identity: {0}")]
    Identity(#[from] KeyError),
}

/// A server's certificate chain and private key.
#[derive(Clone, Debug)]
pub struct ServerIdentity(Arc<CertifiedKey>);

impl ServerIdentity {
    /// Reads a PEM certificate chain and a PEM private key, which must not be encrypted.
    ///
    /// # Errors
    ///
    /// Fails when a file cannot be read, or the key does not match the first certificate.
    pub fn from_pem_files(certificates: &Path, key: &Path) -> Result<Self, TlsSetupError> {
        let read = |path: &Path| {
            fs::read(path).map_err(|error| TlsSetupError::Read {
                path: path.to_owned(),
                reason: error.to_string(),
            })
        };
        let identity = CertifiedKey::from_pem(&read(certificates)?, &read(key)?)?;
        Ok(Self(Arc::new(identity)))
    }

    /// An identity built in memory, such as a test certificate.
    #[must_use]
    pub const fn new(identity: Arc<CertifiedKey>) -> Self {
        Self(identity)
    }

    /// The certificate chain and key.
    pub(crate) fn certified(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.0)
    }
}

/// Fresh randomness and the current time for one handshake.
///
/// # Errors
///
/// Fails when the entropy device cannot be read.
pub(crate) fn handshake_inputs() -> io::Result<(Randomness, u64)> {
    let mut seed = [0; 32];
    File::open(ENTROPY_DEVICE)?.read_exact(&mut seed)?;
    let randomness = Randomness::from_seed(seed);
    seed.fill(0);
    // A clock before the epoch reads as the epoch, which no certificate window holds.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    Ok((randomness, now))
}
