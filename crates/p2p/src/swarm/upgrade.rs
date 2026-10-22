//! Connection upgrade: raw TCP to an authenticated, multiplexed connection.
//!
//! 1. Open the TCP connection.
//! 2. Agree with multistream-select on "/noise" or "/plaintext/2.0.0".
//! 3. Run the security handshake.
//! 4. Agree with multistream-select on "/yamux/1.0.0", inside the secure channel.
//! 5. Start the yamux session.
//!
//! The state machines do the protocol work; this module only moves their bytes.

use std::mem;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::NetworkError;
use crate::{
    identity::PeerId,
    multistream::{Dialer, Listener},
    secure::{Role, SecureSession, SecurityUpgrade},
    yamux,
};

/// Bytes read from the socket per call during the upgrade.
const READ_CHUNK: usize = 4096;

/// A connection that finished the upgrade.
#[derive(Debug)]
pub(super) struct Upgraded {
    /// The socket.
    pub(super) tcp: TcpStream,
    /// The authenticated session and its ciphers.
    pub(super) session: SecureSession,
    /// Plaintext already received that belongs to yamux.
    pub(super) yamux_remainder: Vec<u8>,
}

/// Upgrades one fresh TCP connection, moving the bytes of each negotiation.
#[derive(Debug)]
pub(super) struct Upgrade {
    /// The socket.
    tcp: TcpStream,
    /// Which side of the handshake this node plays.
    role: Role,
    /// Bytes read from the socket per call.
    buffer: [u8; READ_CHUNK],
}

impl Upgrade {
    /// An upgrade of a socket, from one side.
    pub(super) const fn new(tcp: TcpStream, role: Role) -> Self {
        Self {
            tcp,
            role,
            buffer: [0; READ_CHUNK],
        }
    }

    /// Runs the whole upgrade.
    pub(super) async fn run(
        mut self,
        security: &dyn SecurityUpgrade,
        expected: Option<PeerId>,
    ) -> Result<Upgraded, NetworkError> {
        // Phase 1: agree on the security protocol, in the clear.
        let remainder = self.negotiate_raw(security.protocol()).await?;

        // Phase 2: run the handshake, starting with any bytes that trailed the negotiation.
        let mut handshake = security.handshake(self.role, expected);
        let mut input = remainder;
        let mut session = loop {
            let completed = handshake.receive(&input)?;
            // Write whatever the handshake produced, including its final message.
            let output = handshake.take_output();
            if !output.is_empty() {
                self.tcp.write_all(&output).await?;
            }
            if let Some(session) = completed {
                break session;
            }
            input = self.read_some().await?.to_vec();
        };

        // Phase 3: agree on the multiplexer, now through the secure channel.
        let yamux_remainder = self.negotiate_secure(&mut session).await?;
        Ok(Upgraded {
            tcp: self.tcp,
            session,
            yamux_remainder,
        })
    }

    /// Negotiates one protocol on the raw socket, returning the bytes that followed.
    async fn negotiate_raw(&mut self, protocol: &str) -> Result<Vec<u8>, NetworkError> {
        match self.role {
            Role::Initiator => {
                let mut dialer = Dialer::new([protocol])?;
                loop {
                    let output = dialer.take_output();
                    if !output.is_empty() {
                        self.tcp.write_all(&output).await?;
                    }
                    let input = self.read_some().await?;
                    if let Some(negotiated) = dialer.receive(input)? {
                        return Ok(negotiated.remainder);
                    }
                }
            }
            Role::Responder => {
                let mut listener = Listener::new([protocol]);
                loop {
                    let output = listener.take_output();
                    if !output.is_empty() {
                        self.tcp.write_all(&output).await?;
                    }
                    let input = self.read_some().await?;
                    if let Some(negotiated) = listener.receive(input)? {
                        // The echo that confirms the choice must still go out.
                        self.tcp.write_all(&listener.take_output()).await?;
                        return Ok(negotiated.remainder);
                    }
                }
            }
        }
    }

    /// Negotiates yamux inside the secure channel, returning plaintext that followed.
    async fn negotiate_secure(
        &mut self,
        session: &mut SecureSession,
    ) -> Result<Vec<u8>, NetworkError> {
        // Plaintext that arrived with the last handshake message is the first input.
        let mut input = mem::take(&mut session.early_plaintext);
        let mut dialer = match self.role {
            Role::Initiator => Some(Dialer::new([yamux::PROTOCOL])?),
            Role::Responder => None,
        };
        let mut listener = match self.role {
            Role::Initiator => None,
            Role::Responder => Some(Listener::new([yamux::PROTOCOL])),
        };
        loop {
            // Step 1: feed what arrived, if anything.
            let outcome = match (&mut dialer, &mut listener) {
                (Some(dialer), _) if !input.is_empty() => dialer.receive(&input)?,
                (_, Some(listener)) if !input.is_empty() => listener.receive(&input)?,
                _ => None,
            };
            // Step 2: write what the negotiation produced, sealed.
            let output = match (&mut dialer, &mut listener) {
                (Some(dialer), _) => dialer.take_output(),
                (_, Some(listener)) => listener.take_output(),
                _ => Vec::new(),
            };
            if !output.is_empty() {
                let mut wire = Vec::new();
                session.sealer.seal(&output, &mut wire)?;
                self.tcp.write_all(&wire).await?;
            }
            if let Some(negotiated) = outcome {
                return Ok(negotiated.remainder);
            }
            // Step 3: read and unseal more.
            let wire = self.read_some().await?;
            input.clear();
            session.opener.open(wire, &mut input)?;
        }
    }

    /// Reads at least one byte, treating end of stream as an error.
    async fn read_some(&mut self) -> Result<&[u8], NetworkError> {
        let n = self.tcp.read(&mut self.buffer).await?;
        if n == 0 {
            return Err(NetworkError::ConnectionClosed);
        }
        Ok(&self.buffer[..n])
    }
}
