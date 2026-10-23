//! Web PKI: authenticating a server through a certificate path to a trusted root.
//!
//! # Overview
//!
//! A client checks the server's chain in four steps:
//!
//! 1. the server's certificate is usable for server authentication and names the server;
//! 2. a path of CA certificates leads from it to a trusted root;
//! 3. every certificate on the path is valid now, and each CA may issue the next;
//! 4. every name below a constrained CA falls within its name constraints.
//!
//! The rules are those of RFC 5280, section 6, with the server identity of RFC 9525.
//! No revocation is checked, as no consensus client's HTTP stack checks it either.

mod anchor;
mod error;
mod path;
mod server_name;

use std::sync::Arc;

pub use anchor::{LoadSummary, RootStore, TrustAnchor};
pub use error::CertificateError;
pub use path::MAX_INTERMEDIATES;
pub use server_name::{InvalidServerName, ServerName};

use crate::{Verifier, der::Timestamp, x509::PublicKey};

/// Verifies a server under web PKI: a path to one of the roots, for one server name.
#[derive(Clone, Debug)]
pub struct WebPkiVerifier {
    /// The trusted roots, shared by every connection.
    roots: Arc<RootStore>,
    /// The name the server must prove.
    name: ServerName,
}

impl WebPkiVerifier {
    /// A verifier for one server name.
    #[must_use]
    pub const fn new(roots: Arc<RootStore>, name: ServerName) -> Self {
        Self { roots, name }
    }

    /// The name the server must prove.
    #[must_use]
    pub const fn server_name(&self) -> &ServerName {
        &self.name
    }
}

impl Verifier for WebPkiVerifier {
    type Peer = ();
    type Error = CertificateError;

    fn verify(
        &self,
        chain: &[&[u8]],
        now_unix_secs: u64,
    ) -> Result<((), PublicKey), CertificateError> {
        let now = Timestamp::from_unix_secs(now_unix_secs);
        self.roots
            .verify_server(chain, &self.name, now)
            .map(|key| ((), key))
    }
}
