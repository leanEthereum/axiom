//! Connection upgrade: raw TCP to an authenticated, multiplexed connection.
//!
//! ```text
//! TCP ─▶ multistream-select ─▶ security handshake ─▶ multistream-select ─▶ yamux
//!        "/noise" or                                  "/yamux/1.0.0",
//!        "/plaintext/2.0.0"                           inside the secure channel
//! ```
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

/// Runs the whole upgrade on a fresh TCP connection.
pub(super) async fn upgrade(
    mut tcp: TcpStream,
    role: Role,
    security: &dyn SecurityUpgrade,
    expected: Option<PeerId>,
) -> Result<Upgraded, NetworkError> {
    // Phase 1: agree on the security protocol, in the clear.
    let remainder = negotiate_raw(&mut tcp, role, security.protocol()).await?;

    // Phase 2: run the handshake, starting with any bytes that trailed the negotiation.
    let mut handshake = security.handshake(role, expected);
    let mut input = remainder;
    let mut buffer = [0u8; READ_CHUNK];
    let mut session = loop {
        let completed = handshake.receive(&input)?;
        // Write whatever the handshake produced, including its final message.
        let output = handshake.take_output();
        if !output.is_empty() {
            tcp.write_all(&output).await?;
        }
        if let Some(session) = completed {
            break session;
        }
        input = read_some(&mut tcp, &mut buffer).await?.to_vec();
    };

    // Phase 3: agree on the multiplexer, now through the secure channel.
    let yamux_remainder = negotiate_secure(&mut tcp, &mut session, role).await?;
    Ok(Upgraded {
        tcp,
        session,
        yamux_remainder,
    })
}

/// Negotiates one protocol on the raw socket, returning the bytes that followed.
async fn negotiate_raw(
    tcp: &mut TcpStream,
    role: Role,
    protocol: &str,
) -> Result<Vec<u8>, NetworkError> {
    let mut buffer = [0u8; READ_CHUNK];
    match role {
        Role::Initiator => {
            let mut dialer = Dialer::new([protocol])?;
            loop {
                let output = dialer.take_output();
                if !output.is_empty() {
                    tcp.write_all(&output).await?;
                }
                let input = read_some(tcp, &mut buffer).await?;
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
                    tcp.write_all(&output).await?;
                }
                let input = read_some(tcp, &mut buffer).await?;
                if let Some(negotiated) = listener.receive(input)? {
                    // The echo that confirms the choice must still go out.
                    tcp.write_all(&listener.take_output()).await?;
                    return Ok(negotiated.remainder);
                }
            }
        }
    }
}

/// Negotiates yamux inside the secure channel, returning plaintext that followed.
async fn negotiate_secure(
    tcp: &mut TcpStream,
    session: &mut SecureSession,
    role: Role,
) -> Result<Vec<u8>, NetworkError> {
    let mut buffer = [0u8; READ_CHUNK];
    // Plaintext that arrived with the last handshake message is the first input.
    let mut input = mem::take(&mut session.early_plaintext);
    let mut dialer = match role {
        Role::Initiator => Some(Dialer::new([yamux::PROTOCOL])?),
        Role::Responder => None,
    };
    let mut listener = match role {
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
            tcp.write_all(&wire).await?;
        }
        if let Some(negotiated) = outcome {
            return Ok(negotiated.remainder);
        }
        // Step 3: read and unseal more.
        let wire = read_some(tcp, &mut buffer).await?;
        input.clear();
        session.opener.open(wire, &mut input)?;
    }
}

/// Reads at least one byte, treating end of stream as an error.
async fn read_some<'a>(
    tcp: &mut TcpStream,
    buffer: &'a mut [u8],
) -> Result<&'a [u8], NetworkError> {
    let n = tcp.read(buffer).await?;
    if n == 0 {
        return Err(NetworkError::ConnectionClosed);
    }
    Ok(&buffer[..n])
}
