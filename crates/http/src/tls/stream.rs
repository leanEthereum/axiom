//! A TLS connection over a socket, read and written like the socket itself.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use axiom_tls::{CertificateError, Connection, TlsError, Verifier};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::HttpError;

/// Bytes read from the socket at once: one full record and its protection.
const READ_CHUNK: usize = (1 << 14) + 2048 + 5;

/// A socket wrapped in a TLS connection.
///
/// Plaintext written goes out as records at once; records read come back as plaintext.
/// TLS output that the socket could not take yet waits, and the next write or flush sends it first.
#[derive(Debug)]
pub(crate) struct TlsStream<S, V: Verifier> {
    /// The socket.
    socket: S,
    /// The TLS state.
    connection: Connection<V>,
    /// TLS bytes not yet written to the socket.
    pending: Vec<u8>,
    /// Bytes of the pending output already written.
    written: usize,
    /// The buffer socket reads land in.
    scratch: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin, V: Verifier<Error = CertificateError>> TlsStream<S, V> {
    /// Runs the handshake to its end over a socket.
    ///
    /// # Errors
    ///
    /// Fails on a socket error, an early close, or a handshake failure.
    /// A fatal alert goes out to the peer before the error returns.
    pub(crate) async fn handshake(
        mut socket: S,
        mut connection: Connection<V>,
    ) -> Result<Self, HttpError> {
        let mut scratch = vec![0; READ_CHUNK];
        loop {
            let out = connection.take_tls();
            if !out.is_empty() {
                socket.write_all(&out).await?;
                socket.flush().await?;
            }
            if !connection.is_handshaking() {
                break;
            }
            let read = socket.read(&mut scratch).await?;
            if read == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            if let Err(error) = connection.read_tls(&scratch[..read]) {
                // The alert reports the failure; the socket may already be gone, so its error is moot.
                let _ = socket.write_all(&connection.take_tls()).await;
                return Err(HttpError::Tls(error));
            }
        }
        Ok(Self {
            socket,
            connection,
            pending: Vec::new(),
            written: 0,
            scratch,
        })
    }

    /// Moves new TLS output behind what already waits.
    fn queue_output(&mut self) {
        let out = self.connection.take_tls();
        if !out.is_empty() {
            self.pending.extend_from_slice(&out);
        }
    }

    /// Writes waiting TLS output to the socket until none is left.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let written =
                ready!(Pin::new(&mut self.socket).poll_write(cx, &self.pending[self.written..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += written;
        }
        self.pending.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }

    /// A TLS failure as an I/O error, for the stream traits.
    fn io_error(error: &TlsError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error.clone())
    }
}

impl<S, V> AsyncRead for TlsStream<S, V>
where
    S: AsyncRead + AsyncWrite + Unpin,
    V: Verifier<Error = CertificateError> + Unpin,
    V::Peer: Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.connection.has_plaintext() {
                let read = this.connection.read_plaintext(buf.initialize_unfilled());
                buf.advance(read);
                return Poll::Ready(Ok(()));
            }
            // close_notify is the only clean end; without it the data may have been cut short.
            if this.connection.peer_closed() {
                return Poll::Ready(Ok(()));
            }
            let mut socket_buf = ReadBuf::new(&mut this.scratch);
            ready!(Pin::new(&mut this.socket).poll_read(cx, &mut socket_buf))?;
            let read = socket_buf.filled().len();
            if read == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            let result = this.connection.read_tls(&this.scratch[..read]);
            // Answers such as key updates and alerts leave with the next write or flush.
            this.queue_output();
            if let Err(error) = result {
                // Best effort: the alert goes out now if the socket takes it at once.
                let _ = this.poll_drain(cx);
                return Poll::Ready(Err(Self::io_error(&error)));
            }
        }
    }
}

impl<S, V> AsyncWrite for TlsStream<S, V>
where
    S: AsyncRead + AsyncWrite + Unpin,
    V: Verifier<Error = CertificateError> + Unpin,
    V::Peer: Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Earlier output goes first, so at most one write's records wait at a time.
        ready!(this.poll_drain(cx))?;
        this.connection
            .write_plaintext(buf)
            .map_err(|error| Self::io_error(&error))?;
        this.queue_output();
        // The records are queued, so the write is accepted even if the socket takes none yet.
        let _ = this.poll_drain(cx)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.socket).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.connection.close();
        this.queue_output();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.socket).poll_shutdown(cx)
    }
}
