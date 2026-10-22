//! One side of a TLS 1.3 handshake, and the TLS 1.2 client fallback, as a pure state machine.
//!
//! # Overview
//!
//! The transport feeds in the handshake bytes of each encryption level, in stream order.
//! The handshake answers with outputs, which the transport applies in order:
//!
//! - handshake bytes to send at a level;
//! - keys to install for a level;
//! - over TCP, a ChangeCipherSpec record, and key updates.
//!
//! QUIC carries the bytes in CRYPTO frames, per RFC 9001.
//! TCP carries them in TLS records, which the connection layer protects with the installed keys.
//!
//! Server, on the ClientHello at the Initial level:
//!
//! 1. the ServerHello, at the Initial level;
//! 2. the handshake keys;
//! 3. EncryptedExtensions, an optional CertificateRequest, Certificate, CertificateVerify and Finished;
//! 4. the application keys.
//!
//! Client, on the ServerHello: the handshake keys.
//! Then, on the server Finished: its own flight, then the application keys.
//!
//! There is no 0-RTT, no resumption, and no HelloRetryRequest.
//!
//! # Timing
//!
//! Key exchange, the key schedule, and signing run in constant time.
//! Finished messages are compared in constant time.
//! Parsing and signature verification touch only public data.

mod client;
mod config;
pub(crate) mod context;
mod server;

pub use config::{ClientConfig, ServerConfig, Transport};
pub(crate) use context::Context;

use self::{client::Client, server::Server};
use crate::{
    CipherSuite, Level, Randomness, Secrets, Tls12Secrets, TlsError, Verifier, key_schedule::Role,
};

/// What the handshake asks the transport to do next, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsOutput {
    /// Send handshake bytes at a level.
    Handshake {
        /// The level the bytes travel at.
        level: Level,
        /// The handshake messages.
        bytes: Vec<u8>,
    },
    /// Install the TLS 1.3 keys of a level; later output and input at that level use them.
    Keys {
        /// The level the secrets key: handshake or application.
        level: Level,
        /// The secrets.
        secrets: Secrets,
    },
    /// Send a ChangeCipherSpec record, then switch to pending TLS 1.2 keys if any; TCP only.
    ChangeCipherSpec,
    /// Hold TLS 1.2 keys until the ChangeCipherSpec records switch to them; TCP only.
    Tls12Keys(Tls12Secrets),
    /// The peer moved to its next traffic secret; TCP only.
    PeerKeyUpdate {
        /// Whether the peer asks this side to move too.
        update_requested: bool,
    },
}

/// The state machine of one role.
#[derive(Debug)]
enum Machine<V: Verifier> {
    /// The client side.
    Client(Client<V>),
    /// The server side.
    Server(Server<V>),
}

/// One side of a handshake.
#[derive(Debug)]
pub struct Handshake<V: Verifier> {
    /// The role's state machine.
    machine: Machine<V>,
    /// What both roles share.
    context: Context<V>,
    /// The first failure; every later call returns it again.
    error: Option<TlsError<V::Error>>,
}

impl<V: Verifier> Handshake<V> {
    /// The client side; its ClientHello is ready to poll at once.
    ///
    /// # Arguments
    ///
    /// - `config`: what the client offers.
    /// - `verifier`: who checks the server's certificate chain.
    /// - `randomness`: fresh random values from the operating system.
    /// - `now_unix_secs`: seconds since the Unix epoch, for certificate validity.
    #[must_use]
    pub fn client(
        config: ClientConfig,
        verifier: V,
        randomness: Randomness,
        now_unix_secs: u64,
    ) -> Self {
        let mut context = Context::new(Role::Client, Some(verifier), randomness, now_unix_secs);
        let client = Client::start(config, &mut context);
        Self {
            machine: Machine::Client(client),
            context,
            error: None,
        }
    }

    /// The server side, waiting for a ClientHello.
    ///
    /// A verifier is needed only when the configuration requires a client certificate.
    #[must_use]
    pub fn server(
        config: ServerConfig,
        verifier: Option<V>,
        randomness: Randomness,
        now_unix_secs: u64,
    ) -> Self {
        Self {
            machine: Machine::Server(Server::new(config)),
            context: Context::new(Role::Server, verifier, randomness, now_unix_secs),
            error: None,
        }
    }

    /// Restricts the TLS 1.3 suites this side accepts, in order of preference.
    ///
    /// A server picks the first one the client offers.
    /// A client has already offered its suites, and refuses a server choice outside the list.
    #[must_use]
    pub fn with_cipher_suites(mut self, suites: &[CipherSuite]) -> Self {
        match &mut self.machine {
            Machine::Client(client) => client.restrict_suites(suites),
            Machine::Server(server) => server.restrict_suites(suites),
        }
        self
    }

    /// Feeds handshake bytes received at a level, in stream order, in any chunking.
    ///
    /// # Errors
    ///
    /// Fails on a malformed, unexpected, or unauthenticated message, or bytes at the wrong level.
    /// The handshake then stays failed, and every later call returns the same error.
    pub fn read_handshake(&mut self, level: Level, bytes: &[u8]) -> Result<(), TlsError<V::Error>> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        let result = self.read(level, bytes);
        if let Err(error) = &result {
            self.error = Some(error.clone());
            match &mut self.machine {
                Machine::Client(client) => client.fail(),
                Machine::Server(server) => server.fail(),
            }
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
        match &self.machine {
            Machine::Client(client) => !client.is_connected(),
            Machine::Server(server) => !server.is_connected(),
        }
    }

    /// Whether the client negotiated TLS 1.2.
    #[must_use]
    pub const fn is_tls12(&self) -> bool {
        match &self.machine {
            Machine::Client(client) => client.is_tls12(),
            Machine::Server(_) => false,
        }
    }

    /// The level the handshake reads at next.
    #[must_use]
    pub const fn read_level(&self) -> Level {
        self.context.buffer.level()
    }

    /// The negotiated TLS 1.3 suite, once the server hello is sent or received.
    #[must_use]
    pub const fn cipher_suite(&self) -> Option<CipherSuite> {
        self.context.suite
    }

    /// The negotiated application protocol.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.context.alpn.as_deref()
    }

    /// The peer's encoded QUIC transport parameters, once received.
    #[must_use]
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.context.peer_transport_parameters.as_deref()
    }

    /// The authenticated peer, once its certificate verify message checks out.
    #[must_use]
    pub const fn peer(&self) -> Option<&V::Peer> {
        self.context.peer.as_ref()
    }

    /// Buffers the bytes and runs every whole message through the state machine.
    fn read(&mut self, level: Level, bytes: &[u8]) -> Result<(), TlsError<V::Error>> {
        self.context.buffer.push(level, bytes)?;
        while let Some(message) = self.context.buffer.next_message()? {
            match &mut self.machine {
                Machine::Client(client) => client.handle(&message, &mut self.context)?,
                Machine::Server(server) => server.handle(&message, &mut self.context)?,
            }
        }
        Ok(())
    }
}
