//! The two ways a connection carries streams: yamux over a secured TCP socket, or QUIC.
//!
//! # Overview
//!
//! Both offer the same stream calls, so the protocol handlers above never see the difference.
//! They differ in how bytes move:
//!
//! - TCP: a reader task feeds plaintext in; yamux output is sealed and written to the socket.
//! - QUIC: the endpoint task feeds datagrams in; the connection's datagrams go straight to the UDP socket.
//!
//! QUIC also keeps timers, so its connection task wakes at a deadline even when nothing arrives.

use std::{fmt, io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::AsyncWriteExt,
    net::{UdpSocket, tcp::OwnedWriteHalf},
    task::JoinHandle,
    time::Instant,
};

use super::quic::RouteGuard;
use crate::{
    quic::{self, Event},
    secure::Seal,
    yamux::{self, GoAwayCode, Session, SessionEvent},
};

/// A stream of either transport.
///
/// Yamux ids are 32-bit and QUIC ids 62-bit; both fit losslessly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct StreamId(pub(super) u64);

impl StreamId {
    /// The yamux id this stream came from.
    fn yamux(self) -> yamux::StreamId {
        // Invariant: on a TCP connection every stream id came from yamux, so it fits 32 bits.
        yamux::StreamId(u32::try_from(self.0).unwrap_or(u32::MAX))
    }

    /// The QUIC id this stream came from.
    const fn quic(self) -> quic::StreamId {
        quic::StreamId(self.0)
    }
}

impl From<yamux::StreamId> for StreamId {
    fn from(id: yamux::StreamId) -> Self {
        Self(id.0.into())
    }
}

impl From<quic::StreamId> for StreamId {
    fn from(id: quic::StreamId) -> Self {
        Self(id.0)
    }
}

/// What the peer did, in terms both transports share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum MuxEvent {
    /// The peer opened a stream.
    InboundStream(StreamId),
    /// Data arrived on a stream.
    Data {
        /// The stream.
        stream: StreamId,
        /// The bytes, in order.
        data: Vec<u8>,
    },
    /// The peer finished a stream.
    StreamFinished(StreamId),
    /// The peer aborted a stream.
    StreamReset(StreamId),
    /// The connection is ending.
    Closing,
}

/// Yamux over a secured TCP socket.
pub(super) struct TcpLink {
    /// The yamux session.
    pub(super) session: Session,
    /// Seals outbound bytes.
    pub(super) sealer: Box<dyn Seal>,
    /// The socket's write half.
    pub(super) writer: OwnedWriteHalf,
    /// The task reading the socket, stopped when the link drops.
    pub(super) _reader: ReaderGuard,
}

/// A QUIC connection on the endpoint's UDP socket.
pub(super) struct QuicLink {
    /// The connection.
    pub(super) connection: Box<quic::Connection>,
    /// The shared socket.
    pub(super) socket: Arc<UdpSocket>,
    /// The clock origin all QUIC connections share.
    pub(super) origin: Instant,
    /// Removes the connection's routes from the endpoint when the link drops.
    pub(super) _route: RouteGuard,
}

impl QuicLink {
    /// The connection clock.
    pub(super) fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    /// Sends every datagram the connection has ready.
    pub(super) async fn flush(&mut self) -> io::Result<()> {
        let now = self.now();
        while let Some(transmit) = self.connection.poll_transmit(now) {
            self.socket
                .send_to(&transmit.bytes, transmit.destination)
                .await?;
        }
        Ok(())
    }

    /// When the connection must be called back, as a tokio instant.
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.connection.poll_timeout().map(|at| self.origin + at)
    }
}

/// The transport under one connection.
pub(super) enum Transport {
    /// Yamux over TCP.
    Tcp(TcpLink),
    /// QUIC.
    Quic(QuicLink),
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(_) => f.write_str("Transport::Tcp"),
            Self::Quic(link) => write!(f, "Transport::Quic({})", link.connection.remote()),
        }
    }
}

impl Transport {
    /// Opens an outbound stream, or nothing when the transport refuses.
    pub(super) fn open_stream(&mut self) -> Option<StreamId> {
        match self {
            Self::Tcp(link) => link.session.open_stream().ok().map(Into::into),
            Self::Quic(link) => link.connection.open_stream().ok().map(Into::into),
        }
    }

    /// Queues bytes on a stream, returning whether it took them.
    pub(super) fn send(&mut self, stream: StreamId, data: &[u8]) -> bool {
        match self {
            Self::Tcp(link) => link.session.send(stream.yamux(), data).is_ok(),
            Self::Quic(link) => link.connection.send(stream.quic(), data).is_ok(),
        }
    }

    /// Bytes a stream accepts before its send buffer is full.
    pub(super) fn writable(&self, stream: StreamId) -> usize {
        match self {
            Self::Tcp(link) => link.session.writable(stream.yamux()),
            Self::Quic(link) => link.connection.writable(stream.quic()),
        }
    }

    /// Grants the peer credit for consumed bytes.
    pub(super) fn consume(&mut self, stream: StreamId, len: usize) {
        match self {
            Self::Tcp(link) => link.session.consume(stream.yamux(), len),
            Self::Quic(link) => link.connection.consume(stream.quic(), len),
        }
    }

    /// Half-closes a stream after its queued data.
    pub(super) fn close(&mut self, stream: StreamId) {
        match self {
            Self::Tcp(link) => {
                let _ = link.session.close(stream.yamux());
            }
            Self::Quic(link) => {
                let _ = link.connection.close(stream.quic());
            }
        }
    }

    /// Aborts a stream.
    pub(super) fn reset(&mut self, stream: StreamId) {
        match self {
            Self::Tcp(link) => {
                let _ = link.session.reset(stream.yamux());
            }
            Self::Quic(link) => {
                let _ = link.connection.reset(stream.quic());
            }
        }
    }

    /// Whether a stream is still open.
    pub(super) fn is_open(&self, stream: StreamId) -> bool {
        match self {
            Self::Tcp(link) => link.session.is_open(stream.yamux()),
            Self::Quic(link) => link.connection.is_open(stream.quic()),
        }
    }

    /// The next event of the transport.
    pub(super) fn poll_event(&mut self) -> Option<MuxEvent> {
        match self {
            Self::Tcp(link) => loop {
                let event = match link.session.poll_event()? {
                    SessionEvent::InboundStream(stream) => MuxEvent::InboundStream(stream.into()),
                    SessionEvent::Data { stream, data } => MuxEvent::Data {
                        stream: stream.into(),
                        data,
                    },
                    SessionEvent::StreamFinished(stream) => MuxEvent::StreamFinished(stream.into()),
                    SessionEvent::StreamReset(stream) => MuxEvent::StreamReset(stream.into()),
                    SessionEvent::GoAway(_) => MuxEvent::Closing,
                    // Pings are answered inside the session.
                    SessionEvent::Pong(_) => continue,
                };
                return Some(event);
            },
            Self::Quic(link) => loop {
                let event = match link.connection.poll_event()? {
                    Event::InboundStream(stream) => MuxEvent::InboundStream(stream.into()),
                    Event::Data { stream, data } => MuxEvent::Data {
                        stream: stream.into(),
                        data,
                    },
                    Event::StreamFinished(stream) => MuxEvent::StreamFinished(stream.into()),
                    Event::StreamReset(stream) => MuxEvent::StreamReset(stream.into()),
                    Event::Closed(_) => MuxEvent::Closing,
                    // The handshake was reported before the connection started.
                    Event::Connected(_) => continue,
                };
                return Some(event);
            },
        }
    }

    /// Feeds plaintext from the TCP reader, returning false on a protocol error.
    pub(super) fn receive_bytes(&mut self, bytes: &[u8]) -> bool {
        match self {
            // The session queues a go-away with the protocol error code itself.
            Self::Tcp(link) => link.session.receive(bytes).is_ok(),
            Self::Quic(_) => true,
        }
    }

    /// Feeds a datagram from the endpoint.
    pub(super) fn receive_datagram(&mut self, from: SocketAddr, datagram: &[u8]) {
        if let Self::Quic(link) = self {
            let now = link.now();
            link.connection.handle_datagram(now, from, datagram);
        }
    }

    /// Runs the QUIC timers that are due.
    pub(super) fn on_timeout(&mut self) {
        if let Self::Quic(link) = self {
            let now = link.now();
            link.connection.handle_timeout(now);
        }
    }

    /// When the transport must be woken without input, if ever.
    pub(super) fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Tcp(_) => None,
            Self::Quic(link) => link.deadline(),
        }
    }

    /// Whether the transport has ended for good.
    pub(super) fn is_closed(&self) -> bool {
        match self {
            Self::Tcp(_) => false,
            Self::Quic(link) => link.connection.is_closed(),
        }
    }

    /// Writes everything the transport produced.
    pub(super) async fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(link) => {
                let plaintext = link.session.take_output();
                if plaintext.is_empty() {
                    return Ok(());
                }
                let mut wire = Vec::with_capacity(plaintext.len() + 64);
                link.sealer
                    .seal(&plaintext, &mut wire)
                    .map_err(io::Error::other)?;
                link.writer.write_all(&wire).await
            }
            Self::Quic(link) => link.flush().await,
        }
    }

    /// Tells the peer the connection ends, best effort, then stops writing.
    pub(super) async fn shut_down(&mut self) {
        match self {
            Self::Tcp(link) => {
                link.session.go_away(GoAwayCode::Normal);
                let _ = self.flush().await;
                if let Self::Tcp(link) = self {
                    let _ = link.writer.shutdown().await;
                }
            }
            Self::Quic(link) => {
                let now = link.now();
                // Application code 0: a normal close; libp2p assigns no other meaning.
                link.connection.close_connection(now, 0, b"");
                let _ = link.flush().await;
            }
        }
    }
}

/// Aborts the TCP reader task when dropped.
pub(super) struct ReaderGuard(pub(super) JoinHandle<()>);

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        // The reader holds the socket's read half; it must not outlive the connection.
        self.0.abort();
    }
}
