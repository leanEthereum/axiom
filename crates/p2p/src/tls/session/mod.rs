//! One side of a TLS 1.3 handshake, driven by the QUIC transport.
//!
//! # Overview
//!
//! The transport feeds the bytes of each level's CRYPTO stream in.
//! The session answers with outputs, which the transport applies in order:
//! handshake bytes to send at a level, and keys to install for a level.
//!
//! Server, on the ClientHello at the Initial level:
//!
//! 1. the ServerHello, at the Initial level;
//! 2. the handshake keys;
//! 3. EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify and Finished, at the Handshake level;
//! 4. the application keys.
//!
//! Client, on the ServerHello: the handshake keys.
//! Then, on the server Finished: its Certificate, CertificateVerify and Finished, then the application keys.
//!
//! There is no record layer: QUIC protects the bytes itself, per RFC 9001, section 4.
//! There is also no 0-RTT, no resumption, no KeyUpdate message, and no HelloRetryRequest.
//!
//! # Timing
//!
//! The X25519 exchange, the key schedule, and certificate signing run in constant time.
//! Finished messages are compared in constant time.
//! Parsing and signature verification touch only public data.

mod client;
pub(crate) mod context;
mod server;

use std::{collections::VecDeque, mem, sync::Arc};

use axiom_crypto::x25519::SecretKey as KeyShareSecret;
use client::ClientState;
pub(crate) use context::Context;
use server::ServerState;

use super::{
    CipherSuite, Level, TlsError, TlsIdentity, TlsOutput, VerifiedPeer,
    buffer::HandshakeBuffer,
    key_schedule::{Role, Transcript},
    message::ClientHello,
};
use crate::identity::PeerId;

/// The state machine of one role.
#[derive(Debug)]
enum Machine {
    /// The client side.
    Client(ClientState),
    /// The server side.
    Server(ServerState),
}

/// One side of a TLS 1.3 handshake, carried in QUIC CRYPTO frames.
#[derive(Debug)]
pub struct TlsSession {
    /// The role's state machine.
    machine: Machine,
    /// What both roles share.
    context: Context,
    /// The first failure; every later call returns it again.
    error: Option<TlsError>,
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
        let (random, secret) = Self::split_entropy(entropy);
        let mut context = Self::context(
            Role::Client,
            identity,
            transport_parameters,
            expected,
            random,
            now_unix_secs,
        );
        let public = secret.public_key().to_bytes();
        let hello = ClientHello::encode(&random, &public, &context.transport_parameters);
        let hello = context.send(hello);
        context.emit(Level::Initial, hello);
        Self {
            machine: Machine::Client(ClientState::WaitServerHello(secret)),
            context,
            error: None,
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
        let (random, secret) = Self::split_entropy(entropy);
        Self {
            machine: Machine::Server(ServerState::WaitClientHello(secret)),
            context: Self::context(
                Role::Server,
                identity,
                transport_parameters,
                None,
                random,
                now_unix_secs,
            ),
            error: None,
        }
    }

    /// Restricts the suites this side accepts, in order of preference.
    ///
    /// A server picks the first one the client offers.
    /// A client still offers both suites, and refuses a server choice outside the list.
    #[must_use]
    pub fn with_cipher_suites(mut self, suites: &[CipherSuite]) -> Self {
        self.context.suites = suites.to_vec();
        self
    }

    /// Feeds handshake bytes received at a level, in stream order, in any chunking.
    ///
    /// # Errors
    ///
    /// Fails on a malformed, unexpected, or unauthenticated message, or bytes at the wrong level.
    /// The session then stays failed, and every later call returns the same error.
    pub fn read_handshake(&mut self, level: Level, bytes: &[u8]) -> Result<(), TlsError> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        let result = self.read(level, bytes);
        if let Err(error) = &result {
            self.error = Some(error.clone());
            self.machine = Self::failed(self.context.role);
        }
        result
    }

    /// Takes the next output, in the order the transport must apply it.
    pub fn poll_output(&mut self) -> Option<TlsOutput> {
        self.context.output.pop_front()
    }

    /// Whether the handshake is still running on this side.
    ///
    /// It turns false once this side has sent its Finished and checked the peer's.
    #[must_use]
    pub const fn is_handshaking(&self) -> bool {
        !matches!(
            self.machine,
            Machine::Client(ClientState::Connected) | Machine::Server(ServerState::Connected)
        )
    }

    /// The negotiated suite, once the server hello is sent or received.
    #[must_use]
    pub const fn cipher_suite(&self) -> Option<CipherSuite> {
        self.context.suite
    }

    /// The peer's encoded QUIC transport parameters, once received.
    #[must_use]
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.context.peer_transport_parameters.as_deref()
    }

    /// The authenticated peer, once its certificate verify message checks out.
    #[must_use]
    pub const fn peer(&self) -> Option<&VerifiedPeer> {
        self.context.peer.as_ref()
    }

    /// Buffers the bytes and runs every whole message through the state machine.
    fn read(&mut self, level: Level, bytes: &[u8]) -> Result<(), TlsError> {
        self.context.buffer.push(level, bytes)?;
        while let Some(message) = self.context.buffer.next_message()? {
            let failed = Self::failed(self.context.role);
            self.machine = match mem::replace(&mut self.machine, failed) {
                Machine::Client(state) => {
                    Machine::Client(state.handle(&message, &mut self.context)?)
                }
                Machine::Server(state) => {
                    Machine::Server(state.handle(&message, &mut self.context)?)
                }
            };
        }
        Ok(())
    }

    /// The failed state of a role.
    const fn failed(role: Role) -> Machine {
        match role {
            Role::Client => Machine::Client(ClientState::Failed),
            Role::Server => Machine::Server(ServerState::Failed),
        }
    }

    /// The hello random, then the X25519 secret.
    const fn split_entropy(entropy: [u8; 64]) -> ([u8; 32], KeyShareSecret) {
        let (random, secret) = entropy.split_at(32);
        let mut random_bytes = [0; 32];
        random_bytes.copy_from_slice(random);
        let mut secret_bytes = [0; 32];
        secret_bytes.copy_from_slice(secret);
        (random_bytes, KeyShareSecret::from_bytes(secret_bytes))
    }

    /// The shared state of a fresh handshake.
    fn context(
        role: Role,
        identity: Arc<TlsIdentity>,
        transport_parameters: Vec<u8>,
        expected: Option<PeerId>,
        random: [u8; 32],
        now: u64,
    ) -> Context {
        Context {
            role,
            identity,
            transport_parameters,
            expected,
            now,
            random,
            suites: CipherSuite::ALL.to_vec(),
            buffer: HandshakeBuffer::new(Level::Initial),
            transcript: Transcript::new(),
            output: VecDeque::new(),
            suite: None,
            peer_transport_parameters: None,
            peer: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::p256::SecretKey;

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
        // bad_certificate.
        assert_eq!(error.alert(), 42);
        assert!(server.is_handshaking());
        assert_eq!(server.peer(), None);
    }
}
