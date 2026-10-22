//! The UDP exchange with a gateway's NAT-PMP server.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use tokio::{net::UdpSocket, time};

use super::{CodecError, NatError};

/// The port NAT-PMP servers listen on, per RFC 6886 section 3.1.
pub(crate) const PORT_CONTROL_PORT: u16 = 5351;

/// The wait for the first answer; each retry doubles it.
///
/// RFC 6886 section 3.1 starts at 250 ms, the pace of a gateway on the same link.
const FIRST_WAIT: Duration = Duration::from_millis(250);

/// Requests sent before giving up on a gateway.
///
/// Five tries wait 7.75 s in all.
/// The RFC's nine tries over 64 s suit a client with no fallback; this one tries UPnP next.
const ATTEMPTS: u32 = 5;

/// The largest datagram read: a NAT-PMP answer is at most 16 bytes, so more is never one.
const MAX_DATAGRAM: usize = 64;

/// A UDP socket connected to one gateway's port control server.
///
/// A connected socket drops datagrams from any other source.
/// RFC 6886 sections 3.2 and 3.3 require exactly that check of the source address.
#[derive(Debug)]
pub(crate) struct ControlSocket {
    /// The socket, connected to the server.
    socket: UdpSocket,
}

impl ControlSocket {
    /// Opens a socket to a gateway's server.
    ///
    /// # Errors
    ///
    /// Fails when the socket cannot bind or connect.
    pub(crate) async fn connect(server: SocketAddr) -> Result<Self, NatError> {
        let io = |context| move |error| NatError::Io { context, error };
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(io("binding the port control socket"))?;
        socket
            .connect(server)
            .await
            .map_err(io("connecting to the port control server"))?;
        Ok(Self { socket })
    }

    /// Sends a request until an answer decodes, doubling the wait each time.
    ///
    /// Stray or garbled datagrams are skipped.
    /// A refusal or a version mismatch ends the exchange at once, since resending cannot change it.
    ///
    /// # Errors
    ///
    /// Fails on a socket error, such as the port being unreachable, on a definitive refusal,
    /// and after the last attempt goes unanswered.
    pub(crate) async fn exchange<T>(
        &self,
        request: &[u8],
        read: impl Fn(&[u8]) -> Result<T, CodecError>,
    ) -> Result<T, NatError> {
        self.exchange_with(request, read, ATTEMPTS).await
    }

    /// Sends a request with a set number of attempts.
    ///
    /// Deletions use fewer: RFC 6886 section 3.1 calls them advisory.
    pub(crate) async fn exchange_with<T>(
        &self,
        request: &[u8],
        read: impl Fn(&[u8]) -> Result<T, CodecError>,
        attempts: u32,
    ) -> Result<T, NatError> {
        let mut buffer = [0; MAX_DATAGRAM];
        let mut wait = FIRST_WAIT;
        let mut waited = Duration::ZERO;
        for _ in 0..attempts {
            self.socket
                .send(request)
                .await
                .map_err(|error| NatError::Io {
                    context: "sending to the port control server",
                    error,
                })?;
            let deadline = time::Instant::now() + wait;
            loop {
                let Ok(received) = time::timeout_at(deadline, self.socket.recv(&mut buffer)).await
                else {
                    break;
                };
                // Port unreachable arrives here as a refused connection: no server listens.
                let length = received.map_err(|error| NatError::Io {
                    context: "receiving from the port control server",
                    error,
                })?;
                match read(&buffer[..length]) {
                    Ok(answer) => return Ok(answer),
                    Err(
                        error
                        @ (CodecError::Refused { .. } | CodecError::UnsupportedVersion { .. }),
                    ) => return Err(error.into()),
                    // Anything else answers no request of ours: keep listening.
                    Err(_) => {}
                }
            }
            waited += wait;
            wait *= 2;
        }
        Err(NatError::Timeout { attempts, waited })
    }
}
