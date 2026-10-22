//! The byte stream under one HTTP connection: plain TCP, or TLS over TCP.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use axiom_tls::{
    ClientConfig, Connection, NoClientCertificate, ServerConfig,
    pki::{ServerName, WebPkiVerifier},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use crate::{
    HttpError,
    tls::{ServerIdentity, TlsStream, TrustRoots, handshake_inputs},
};

/// The stream one connection reads and writes.
#[derive(Debug)]
pub(crate) enum Transport {
    /// Plain TCP.
    Plain(TcpStream),
    /// TLS as a client, the server checked under web PKI.
    Client(Box<TlsStream<TcpStream, WebPkiVerifier>>),
    /// TLS as a server, with no client certificate.
    Server(Box<TlsStream<TcpStream, NoClientCertificate>>),
}

impl Transport {
    /// Runs a client handshake with a server known by a host name or address.
    ///
    /// The server name travels in the hello when it is a DNS name, per RFC 6066, section 3.
    pub(crate) async fn connect_tls(
        socket: TcpStream,
        host: &str,
        roots: TrustRoots,
    ) -> Result<Self, HttpError> {
        let name: ServerName = host.parse().map_err(|_| HttpError::InvalidUrl)?;
        let config = ClientConfig::https(name.dns_name().map(str::to_owned));
        let verifier = WebPkiVerifier::new(roots.store(), name);
        let (randomness, now) = handshake_inputs()?;
        let connection = Connection::client(config, verifier, randomness, now);
        let stream = TlsStream::handshake(socket, connection).await?;
        Ok(Self::Client(Box::new(stream)))
    }

    /// Runs a server handshake under an identity.
    pub(crate) async fn accept_tls(
        socket: TcpStream,
        identity: &ServerIdentity,
    ) -> Result<Self, HttpError> {
        let config = ServerConfig::https(identity.certified());
        let (randomness, now) = handshake_inputs()?;
        let connection = Connection::server(config, None, randomness, now);
        let stream = TlsStream::handshake(socket, connection).await?;
        Ok(Self::Server(Box::new(stream)))
    }
}

impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Client(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
            Self::Server(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Client(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
            Self::Server(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Client(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
            Self::Server(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Client(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
            Self::Server(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}
