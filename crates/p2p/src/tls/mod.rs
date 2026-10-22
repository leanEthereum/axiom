//! TLS 1.3 for QUIC, with libp2p peer authentication.
//!
//! Placeholder interface: the handshake refuses everything until the implementation lands.
//! The signatures below are the contract between the TLS handshake and the QUIC transport.

use std::{collections::VecDeque, sync::Arc};

use axiom_crypto::hkdf::Hkdf;
use thiserror::Error;

use crate::identity::{Keypair, PeerId, PublicKey};

/// The ALPN protocol identifier libp2p negotiates over QUIC.
pub const ALPN: &[u8] = b"libp2p";

/// The QUIC encryption level a handshake message travels at, per RFC 9001, section 4.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Level {
    /// Initial packets, keyed from the destination connection id.
    Initial,
    /// Handshake packets.
    Handshake,
    /// 1-RTT packets.
    Application,
}

/// A TLS 1.3 cipher suite this stack negotiates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256, code point 0x1301.
    Aes128GcmSha256,
    /// TLS_CHACHA20_POLY1305_SHA256, code point 0x1303.
    ChaCha20Poly1305Sha256,
}

/// A 32-byte traffic secret and the suite whose hash and AEAD it keys.
///
/// The bytes clear when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct TrafficSecret {
    /// The suite the secret belongs to.
    suite: CipherSuite,
    /// The secret.
    secret: [u8; 32],
}

impl TrafficSecret {
    /// Wraps secret bytes under a suite.
    #[must_use]
    pub const fn new(suite: CipherSuite, secret: [u8; 32]) -> Self {
        Self { suite, secret }
    }

    /// The suite the secret belongs to.
    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// The secret bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Fills an output with HKDF-Expand-Label of this secret, per RFC 8446, section 7.1.
    ///
    /// The label is given without the "tls13 " prefix, which the function adds.
    pub fn expand_label(&self, label: &[u8], context: &[u8], out: &mut [u8]) {
        let mut info = Vec::with_capacity(4 + 6 + label.len() + context.len());
        // Invariant: outputs and labels here are at most 255 bytes, as every caller's are.
        info.extend_from_slice(&(out.len() as u16).to_be_bytes());
        info.push((6 + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        // Invariant: every output is far below the 255 * 32 bytes HKDF-SHA256 can expand.
        let _ = Hkdf::from_prk(self.secret).expand(&info, out);
    }

    /// The secret derived under a label with an empty context, keeping the suite.
    #[must_use]
    pub fn derive(&self, label: &[u8]) -> Self {
        let mut secret = [0; 32];
        self.expand_label(label, &[], &mut secret);
        Self::new(self.suite, secret)
    }
}

impl Drop for TrafficSecret {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

impl core::fmt::Debug for TrafficSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrafficSecret")
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

/// The traffic secrets of one level, one per direction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secrets {
    /// Protects what this side sends.
    pub local: TrafficSecret,
    /// Protects what the peer sends.
    pub remote: TrafficSecret,
}

/// What the handshake asks the transport to do next, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsOutput {
    /// Send handshake bytes at a level, in CRYPTO frames.
    Handshake {
        /// The level the bytes travel at.
        level: Level,
        /// The handshake messages.
        bytes: Vec<u8>,
    },
    /// Install the keys of a level; later output and input at that level use them.
    Keys {
        /// The level the secrets key: handshake or application.
        level: Level,
        /// The secrets.
        secrets: Secrets,
    },
}

/// A peer authenticated by its libp2p certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPeer {
    /// The peer identifier derived from the host key.
    pub peer_id: PeerId,
    /// The host key the certificate extension carries.
    pub public_key: PublicKey,
}

/// A handshake failure, with the TLS alert it maps to.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TlsError {
    /// The handshake is not implemented yet.
    #[error("TLS handshake unavailable")]
    Unavailable,
}

impl TlsError {
    /// The TLS alert description, per RFC 8446, section 6.
    ///
    /// QUIC closes with the crypto error 0x100 plus this value, per RFC 9001, section 4.8.
    #[must_use]
    pub const fn alert(&self) -> u8 {
        match self {
            // internal_error.
            Self::Unavailable => 80,
        }
    }
}

/// This node's TLS identity: an ephemeral certificate key and its libp2p certificate.
#[derive(Debug)]
pub struct TlsIdentity {
    /// The DER certificate.
    certificate: Vec<u8>,
}

impl TlsIdentity {
    /// A fresh self-signed certificate binding the host key.
    ///
    /// # Arguments
    ///
    /// - `host`: the secp256k1 identity, which signs the extension.
    /// - `seed`: 32 bytes of operating system entropy for the certificate key.
    ///
    /// # Errors
    ///
    /// Fails when the seed gives no valid key.
    pub const fn generate(_host: &Keypair, _seed: [u8; 32]) -> Result<Self, TlsError> {
        Err(TlsError::Unavailable)
    }

    /// The DER certificate.
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
}

/// One side of a TLS 1.3 handshake, carried in QUIC CRYPTO frames.
#[derive(Debug)]
pub struct TlsSession {
    /// Output not yet taken.
    output: VecDeque<TlsOutput>,
}

impl TlsSession {
    /// The client side.
    ///
    /// # Arguments
    ///
    /// - `identity`: this node's certificate and key.
    /// - `transport_parameters`: this side's encoded QUIC transport parameters.
    /// - `expected`: the peer the dialer means to reach, if known.
    /// - `entropy`: 64 bytes of operating system entropy: the random, then the key share secret.
    /// - `now`: seconds since the Unix epoch, for the certificate validity check.
    #[must_use]
    pub fn client(
        _identity: Arc<TlsIdentity>,
        _transport_parameters: Vec<u8>,
        _expected: Option<PeerId>,
        _entropy: [u8; 64],
        _now: u64,
    ) -> Self {
        Self {
            output: VecDeque::new(),
        }
    }

    /// The server side, with the same arguments as the client but no expected peer.
    #[must_use]
    pub fn server(
        _identity: Arc<TlsIdentity>,
        _transport_parameters: Vec<u8>,
        _entropy: [u8; 64],
        _now: u64,
    ) -> Self {
        Self {
            output: VecDeque::new(),
        }
    }

    /// Feeds handshake bytes received at a level, in stream order, in any chunking.
    ///
    /// # Errors
    ///
    /// Fails on a malformed, unexpected, or unauthenticated message.
    pub const fn read_handshake(&mut self, _level: Level, _bytes: &[u8]) -> Result<(), TlsError> {
        Err(TlsError::Unavailable)
    }

    /// Takes the next output, in the order the transport must apply it.
    pub fn poll_output(&mut self) -> Option<TlsOutput> {
        self.output.pop_front()
    }

    /// Whether the handshake is still running on this side.
    #[must_use]
    pub const fn is_handshaking(&self) -> bool {
        true
    }

    /// The negotiated suite, once the server hello is sent or received.
    #[must_use]
    pub const fn cipher_suite(&self) -> Option<CipherSuite> {
        None
    }

    /// The peer's encoded QUIC transport parameters, once received.
    #[must_use]
    pub const fn peer_transport_parameters(&self) -> Option<&[u8]> {
        None
    }

    /// The authenticated peer, once its certificate verify message checks out.
    #[must_use]
    pub const fn peer(&self) -> Option<&VerifiedPeer> {
        None
    }
}
