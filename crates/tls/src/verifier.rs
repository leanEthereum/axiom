//! Who checks the peer's certificates: the one policy a handshake leaves open.
//!
//! The handshake itself only proves the peer holds the key its certificate names.
//! Whether that certificate deserves trust is a profile's choice:
//!
//! - web PKI walks a path to a trusted root and matches the server name;
//! - libp2p checks a self-signed certificate that binds a host key.

use std::fmt;

use crate::{CertificateRejection, x509::PublicKey};

/// Checks a peer's certificate chain and names the key that must sign the handshake.
pub trait Verifier {
    /// What a verified chain proves about the peer.
    type Peer: Clone + fmt::Debug;

    /// Why a chain is refused.
    type Error: CertificateRejection;

    /// Checks a chain, the peer's own certificate first, at a time in seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Fails when the chain does not authenticate the peer.
    fn verify(
        &self,
        chain: &[&[u8]],
        now_unix_secs: u64,
    ) -> Result<(Self::Peer, PublicKey), Self::Error>;
}
