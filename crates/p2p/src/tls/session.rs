//! One side of a libp2p TLS handshake, driven by the QUIC transport.

use std::sync::Arc;

use axiom_tls::{
    ClientConfig, Handshake, NamedGroup, Randomness, ServerConfig, SignatureScheme, Transport,
};

use super::{
    ALPN, CipherSuite, Level, TlsError, TlsIdentity, TlsOutput, VerifiedPeer, peer::Libp2pVerifier,
};
use crate::identity::PeerId;

/// One side of a TLS 1.3 handshake under the libp2p profile, carried in QUIC CRYPTO frames.
#[derive(Debug)]
pub struct TlsSession {
    /// The handshake.
    handshake: Handshake<Libp2pVerifier>,
}

impl TlsSession {
    /// The client side; its ClientHello is ready to poll at once.
    ///
    /// # Arguments
    ///
    /// - `identity`: this node's certificate and key.
    /// - `transport_parameters`: this side's encoded QUIC transport parameters.
    /// - `expected`: the peer the dialer means to reach, if known.
    /// - `entropy`: 64 bytes of operating system entropy: the random, then the key share secret.
    /// - `now_unix_secs`: seconds since the Unix epoch, for the certificate validity check.
    #[must_use]
    pub fn client(
        identity: Arc<TlsIdentity>,
        transport_parameters: Vec<u8>,
        expected: Option<PeerId>,
        entropy: [u8; 64],
        now_unix_secs: u64,
    ) -> Self {
        let config = ClientConfig {
            suites: CipherSuite::ALL.to_vec(),
            tls12_suites: Vec::new(),
            groups: vec![NamedGroup::X25519],
            signature_schemes: vec![SignatureScheme::ECDSA_SECP256R1_SHA256],
            alpn: vec![ALPN.to_vec()],
            require_alpn: true,
            server_name: None,
            transport: Transport::Quic {
                parameters: transport_parameters,
            },
            identity: Some(identity.certified()),
        };
        Self {
            handshake: Handshake::client(
                config,
                Libp2pVerifier { expected },
                Self::randomness(entropy),
                now_unix_secs,
            ),
        }
    }

    /// The server side, with the same arguments as the client but no expected peer.
    #[must_use]
    pub fn server(
        identity: Arc<TlsIdentity>,
        transport_parameters: Vec<u8>,
        entropy: [u8; 64],
        now_unix_secs: u64,
    ) -> Self {
        let config = ServerConfig {
            suites: CipherSuite::ALL.to_vec(),
            groups: vec![NamedGroup::X25519],
            identity: identity.certified(),
            alpn: vec![ALPN.to_vec()],
            require_alpn: true,
            client_auth: Some(vec![SignatureScheme::ECDSA_SECP256R1_SHA256]),
            transport: Transport::Quic {
                parameters: transport_parameters,
            },
        };
        Self {
            handshake: Handshake::server(
                config,
                Some(Libp2pVerifier::default()),
                Self::randomness(entropy),
                now_unix_secs,
            ),
        }
    }

    /// Restricts the suites this side accepts, in order of preference.
    ///
    /// A server picks the first one the client offers.
    /// A client still offers both suites, and refuses a server choice outside the list.
    #[must_use]
    pub fn with_cipher_suites(self, suites: &[CipherSuite]) -> Self {
        Self {
            handshake: self.handshake.with_cipher_suites(suites),
        }
    }

    /// Feeds handshake bytes received at a level, in stream order, in any chunking.
    ///
    /// # Errors
    ///
    /// Fails on a malformed, unexpected, or unauthenticated message, or bytes at the wrong level.
    /// The session then stays failed, and every later call returns the same error.
    pub fn read_handshake(&mut self, level: Level, bytes: &[u8]) -> Result<(), TlsError> {
        self.handshake.read_handshake(level, bytes)
    }

    /// Takes the next output, in the order the transport must apply it.
    pub fn poll_output(&mut self) -> Option<TlsOutput> {
        self.handshake.poll_output()
    }

    /// Whether the handshake is still running on this side.
    ///
    /// It turns false once this side has sent its Finished and checked the peer's.
    #[must_use]
    pub const fn is_handshaking(&self) -> bool {
        self.handshake.is_handshaking()
    }

    /// The negotiated suite, once the server hello is sent or received.
    #[must_use]
    pub const fn cipher_suite(&self) -> Option<CipherSuite> {
        self.handshake.cipher_suite()
    }

    /// The peer's encoded QUIC transport parameters, once received.
    #[must_use]
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.handshake.peer_transport_parameters()
    }

    /// The authenticated peer, once its certificate verify message checks out.
    #[must_use]
    pub const fn peer(&self) -> Option<&VerifiedPeer> {
        self.handshake.peer()
    }

    /// The handshake randomness: the hello random and the X25519 secret, as the entropy gives them.
    ///
    /// The profile uses no P-256 share, session id, or PSS salt, so those expand from the random.
    fn randomness(entropy: [u8; 64]) -> Randomness {
        let (random, secret) = entropy.split_at(32);
        let mut random_bytes = [0; 32];
        random_bytes.copy_from_slice(random);
        let mut randomness = Randomness::from_seed(random_bytes);
        randomness.random = random_bytes;
        randomness.x25519.copy_from_slice(secret);
        randomness
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::p256::SecretKey;
    use axiom_tls::Alert;

    use super::*;
    use crate::{
        identity::Keypair,
        tls::{CertificateError, certificate::CertificateBuilder},
    };

    /// Moves every pending flight of one side into the other, returning the first error.
    fn deliver(from: &mut TlsSession, to: &mut TlsSession) -> Result<(), TlsError> {
        while let Some(output) = from.poll_output() {
            if let TlsOutput::Handshake { level, bytes } = output {
                to.read_handshake(level, &bytes)?;
            }
        }
        Ok(())
    }

    #[test]
    fn client_certificate_without_the_extension_is_refused() {
        // Fixture state: the client presents a well-signed certificate with no extensions at all.
        let key = SecretKey::from_bytes(&[7; 32]).unwrap();
        let bare = {
            let builder = CertificateBuilder::new(&key);
            builder.sign(|fields| builder.fields(fields, |_| {}))
        };
        let client_identity = Arc::new(TlsIdentity::with_certificate(key, bare));
        let host = Keypair::from_secret_bytes(&[8; 32]).unwrap();
        let server_identity = Arc::new(TlsIdentity::generate(&host, [9; 32]).unwrap());
        let mut client = TlsSession::client(client_identity, vec![1], None, [1; 64], 1_792_000_000);
        let mut server = TlsSession::server(server_identity, vec![2], [2; 64], 1_792_000_000);

        // ClientHello, server flight, then the client flight the server refuses.
        assert_eq!(deliver(&mut client, &mut server), Ok(()));
        assert_eq!(deliver(&mut server, &mut client), Ok(()));
        let error = deliver(&mut client, &mut server).unwrap_err();
        assert_eq!(
            error,
            TlsError::Certificate(CertificateError::MissingExtension)
        );
        assert_eq!(error.alert(), Alert::BAD_CERTIFICATE);
        assert!(server.is_handshaking());
        assert_eq!(server.peer(), None);
    }
}
