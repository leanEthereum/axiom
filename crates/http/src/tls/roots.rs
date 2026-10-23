//! The roots a client trusts: the platform's certificate bundle, plus any the operator names.

use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use axiom_tls::pki::RootStore;

use super::TlsSetupError;

/// Bundle files the common platforms install, in the order they are tried.
///
/// - Debian, Ubuntu, Arch, Gentoo: /etc/ssl/certs/ca-certificates.crt
/// - Fedora and RHEL: the two pki paths
/// - openSUSE: /etc/ssl/ca-bundle.pem
/// - Alpine, macOS and the BSDs: /etc/ssl/cert.pem and the FreeBSD ports path
const BUNDLE_FILES: [&str; 7] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/ssl/cert.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
];

/// Directories of one certificate per file, read when no bundle file exists.
const BUNDLE_DIRECTORIES: [&str; 2] = ["/etc/ssl/certs", "/etc/pki/tls/certs"];

/// The environment variable naming a bundle file, as OpenSSL reads it.
const CERT_FILE_VARIABLE: &str = "SSL_CERT_FILE";

/// The environment variable naming a directory of certificates, as OpenSSL reads it.
const CERT_DIR_VARIABLE: &str = "SSL_CERT_DIR";

/// The system roots, loaded once per process.
static SYSTEM: OnceLock<Result<Arc<RootStore>, TlsSetupError>> = OnceLock::new();

/// The certificates a client accepts as roots of a server's chain.
#[derive(Clone, Debug)]
pub struct TrustRoots(Arc<RootStore>);

impl TrustRoots {
    /// The platform's roots, read once from its bundle.
    ///
    /// SSL_CERT_FILE and SSL_CERT_DIR override the platform paths, as OpenSSL reads them.
    ///
    /// # Errors
    ///
    /// Fails when no bundle holds a usable root.
    pub fn system() -> Result<Self, TlsSetupError> {
        SYSTEM
            .get_or_init(|| Self::load_system().map(Arc::new))
            .clone()
            .map(Self)
    }

    /// The platform's roots plus the certificates of PEM files.
    ///
    /// # Errors
    ///
    /// Fails when the platform has no roots or a file cannot be read or holds no certificate.
    pub fn with_files(files: &[PathBuf]) -> Result<Self, TlsSetupError> {
        let mut store = (*Self::system()?.0).clone();
        for file in files {
            let added = Self::add_file(&mut store, file)?;
            if added == 0 {
                return Err(TlsSetupError::NoCertificate { path: file.clone() });
            }
        }
        Ok(Self(Arc::new(store)))
    }

    /// Roots given directly, such as a test authority.
    #[must_use]
    pub const fn from_store(store: Arc<RootStore>) -> Self {
        Self(store)
    }

    /// The root store.
    #[must_use]
    pub fn store(&self) -> Arc<RootStore> {
        Arc::clone(&self.0)
    }

    /// Reads the bundle the environment or the platform names.
    fn load_system() -> Result<RootStore, TlsSetupError> {
        let mut store = RootStore::new();
        let file = env::var_os(CERT_FILE_VARIABLE).map(PathBuf::from);
        let directory = env::var_os(CERT_DIR_VARIABLE).map(PathBuf::from);
        if file.is_some() || directory.is_some() {
            if let Some(file) = file {
                Self::add_file(&mut store, &file)?;
            }
            if let Some(directory) = directory {
                Self::add_directory(&mut store, &directory);
            }
        } else if let Some(file) = BUNDLE_FILES
            .iter()
            .map(Path::new)
            .find(|path| path.is_file())
        {
            Self::add_file(&mut store, file)?;
        } else {
            for directory in BUNDLE_DIRECTORIES {
                Self::add_directory(&mut store, Path::new(directory));
            }
        }
        if store.is_empty() {
            return Err(TlsSetupError::NoRoots);
        }
        Ok(store)
    }

    /// Adds every usable certificate of one PEM file, returning how many.
    fn add_file(store: &mut RootStore, path: &Path) -> Result<usize, TlsSetupError> {
        let pem = fs::read(path).map_err(|error| TlsSetupError::Read {
            path: path.to_owned(),
            reason: error.to_string(),
        })?;
        let summary = store
            .add_pem_bundle(&pem)
            .map_err(|source| TlsSetupError::Pem {
                path: path.to_owned(),
                source,
            })?;
        Ok(summary.added)
    }

    /// Adds the certificates of every readable PEM file in a directory, skipping the rest.
    fn add_directory(store: &mut RootStore, directory: &Path) {
        let Ok(entries) = fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                // A directory mixes formats and links; a file that is not PEM anchors nothing.
                let _ = Self::add_file(store, &path);
            }
        }
    }
}
