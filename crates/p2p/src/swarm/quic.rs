//! The QUIC endpoint task: one UDP socket shared by every QUIC connection.
//!
//! # Overview
//!
//! Three kinds of task share the socket:
//!
//! 1. A reader task receives datagrams and hands them to the endpoint task.
//! 2. The endpoint task routes each datagram to its connection, or accepts a new one.
//! 3. Each connection task sends its own datagrams straight to the socket.
//!
//! A datagram for a connection whose queue is full is dropped, as the network might drop it.
//! QUIC's loss recovery repairs it, so the endpoint never waits on one slow connection.

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{
    net::UdpSocket,
    spawn,
    sync::mpsc::{self, error::TrySendError},
    task::JoinHandle,
    time::{Instant, timeout_at},
};

use super::{
    connection::{ConnectionId, ConnectionInput},
    driver::SwarmInput,
    transport::QuicLink,
};
use crate::{
    identity::PeerId,
    quic::{Connection, ConnectionHandle, DatagramEvent, Endpoint, Event},
    tls::VerifiedPeer,
};

/// The largest UDP payload read; QUIC datagrams never exceed 65527 bytes.
const MAX_DATAGRAM: usize = 65_535;

/// Datagrams waiting for the endpoint task before the reader drops more.
const ENDPOINT_QUEUE: usize = 1024;

/// Seconds since the Unix epoch, for certificate validity.
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// What the endpoint task waits on.
#[derive(Debug)]
pub(super) enum EndpointInput {
    /// A datagram arrived on the socket.
    Datagram(SocketAddr, Vec<u8>),
    /// Dial a peer.
    Connect {
        /// The swarm's id for the connection.
        id: ConnectionId,
        /// The peer's socket.
        remote: SocketAddr,
        /// The peer the dialer means to reach.
        expected: Option<PeerId>,
    },
    /// A connection ended; stop routing to it.
    Forget(ConnectionHandle),
}

/// A QUIC connection ready for its task, sent from the endpoint to the swarm.
#[derive(Debug)]
pub(super) struct QuicStart {
    /// The swarm's id for a dialed connection; accepted ones get theirs from the swarm.
    pub(super) id: Option<ConnectionId>,
    /// The endpoint's handle.
    pub(super) handle: ConnectionHandle,
    /// The connection.
    pub(super) connection: Box<Connection>,
    /// The connection task's input, which the endpoint routes datagrams into.
    pub(super) sender: mpsc::Sender<ConnectionInput>,
    /// The other end of that input.
    pub(super) receiver: mpsc::Receiver<ConnectionInput>,
}

/// Removes a connection's routes from the endpoint when dropped.
#[derive(Debug)]
pub(super) struct RouteGuard {
    /// The endpoint's input.
    endpoint: mpsc::Sender<EndpointInput>,
    /// The connection.
    handle: ConnectionHandle,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        // A full queue loses the route removal; the next one to the same handle never comes,
        // so the stale route only costs a dropped datagram per stray packet.
        let _ = self.endpoint.try_send(EndpointInput::Forget(self.handle));
    }
}

/// The socket, the endpoint's input, and the clock origin connection tasks share.
#[derive(Clone, Debug)]
pub(super) struct QuicShared {
    /// The UDP socket.
    pub(super) socket: Arc<UdpSocket>,
    /// The endpoint task's input.
    pub(super) endpoint: mpsc::Sender<EndpointInput>,
    /// The clock origin of every QUIC connection.
    pub(super) origin: Instant,
}

impl QuicShared {
    /// Starts the endpoint and reader tasks on a bound socket.
    ///
    /// # Returns
    ///
    /// The shared handles, and the two tasks to stop at shutdown.
    pub(super) fn start(
        socket: UdpSocket,
        endpoint: Endpoint,
        swarm: mpsc::Sender<SwarmInput>,
        connection_queue: usize,
    ) -> (Self, [JoinHandle<()>; 2]) {
        let socket = Arc::new(socket);
        let origin = Instant::now();
        let (input_tx, input_rx) = mpsc::channel(ENDPOINT_QUEUE);
        let shared = Self {
            socket: Arc::clone(&socket),
            endpoint: input_tx.clone(),
            origin,
        };
        let reader = spawn(Self::read(Arc::clone(&socket), input_tx));
        let task = EndpointTask {
            endpoint,
            shared: shared.clone(),
            routes: HashMap::new(),
            swarm,
            connection_queue,
        };
        let driver = spawn(task.run(input_rx));
        (shared, [reader, driver])
    }

    /// Reads the socket and forwards datagrams, dropping them when the endpoint falls behind.
    async fn read(socket: Arc<UdpSocket>, endpoint: mpsc::Sender<EndpointInput>) {
        let mut buffer = vec![0; MAX_DATAGRAM];
        loop {
            let Ok((len, from)) = socket.recv_from(&mut buffer).await else {
                // ICMP errors surface as failed reads on some platforms; they end nothing.
                continue;
            };
            match endpoint.try_send(EndpointInput::Datagram(from, buffer[..len].to_vec())) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Closed(_)) => return,
            }
        }
    }

    /// The link of a started connection.
    pub(super) fn link(&self, connection: Box<Connection>, handle: ConnectionHandle) -> QuicLink {
        QuicLink {
            connection,
            socket: Arc::clone(&self.socket),
            origin: self.origin,
            _route: RouteGuard {
                endpoint: self.endpoint.clone(),
                handle,
            },
        }
    }

    /// The connection clock.
    pub(super) fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// The endpoint task's state.
struct EndpointTask {
    /// The routing state machine.
    endpoint: Endpoint,
    /// The socket and clock.
    shared: QuicShared,
    /// Each connection task's input.
    routes: HashMap<ConnectionHandle, mpsc::Sender<ConnectionInput>>,
    /// The swarm task's input.
    swarm: mpsc::Sender<SwarmInput>,
    /// Capacity of each connection's input queue.
    connection_queue: usize,
}

impl EndpointTask {
    /// Handles inputs until the swarm stops.
    async fn run(mut self, mut inputs: mpsc::Receiver<EndpointInput>) {
        while let Some(input) = inputs.recv().await {
            if !self.handle(input).await {
                return;
            }
        }
    }

    /// Handles one input, returning false once the swarm is gone.
    async fn handle(&mut self, input: EndpointInput) -> bool {
        let now = self.shared.now();
        match input {
            EndpointInput::Datagram(from, bytes) => {
                match self.endpoint.handle(now, unix_seconds(), from, &bytes) {
                    Some(DatagramEvent::Route(handle)) => {
                        if let Some(route) = self.routes.get(&handle) {
                            // A full queue drops the datagram; QUIC retransmits.
                            let _ = route.try_send(ConnectionInput::Datagram(from, bytes));
                        }
                    }
                    Some(DatagramEvent::Accept(handle, connection)) => {
                        return self.start(None, handle, connection).await;
                    }
                    Some(DatagramEvent::Respond(transmit)) => {
                        let _ = self
                            .shared
                            .socket
                            .send_to(&transmit.bytes, transmit.destination)
                            .await;
                    }
                    None => {}
                }
            }
            EndpointInput::Connect {
                id,
                remote,
                expected,
            } => {
                let (handle, connection) =
                    self.endpoint.connect(remote, expected, now, unix_seconds());
                return self.start(Some(id), handle, Box::new(connection)).await;
            }
            EndpointInput::Forget(handle) => {
                self.endpoint.forget(handle);
                self.routes.remove(&handle);
            }
        }
        true
    }

    /// Routes a new connection to a fresh queue and hands it to the swarm.
    async fn start(
        &mut self,
        id: Option<ConnectionId>,
        handle: ConnectionHandle,
        connection: Box<Connection>,
    ) -> bool {
        let (sender, receiver) = mpsc::channel(self.connection_queue.max(1));
        self.routes.insert(handle, sender.clone());
        let start = QuicStart {
            id,
            handle,
            connection,
            sender,
            receiver,
        };
        self.swarm.send(SwarmInput::Quic(start)).await.is_ok()
    }
}

/// Drives a connection until its handshake completes.
///
/// # Returns
///
/// The authenticated peer, or why the handshake failed.
pub(super) async fn handshake(
    link: &mut QuicLink,
    inputs: &mut mpsc::Receiver<ConnectionInput>,
) -> Result<VerifiedPeer, String> {
    loop {
        link.flush().await.map_err(|error| error.to_string())?;
        while let Some(event) = link.connection.poll_event() {
            match event {
                Event::Connected(peer) => return Ok(peer),
                Event::Closed(error) => return Err(error.to_string()),
                // Nothing else can happen before the handshake completes.
                _ => {}
            }
        }
        let input = match link.deadline() {
            Some(deadline) => match timeout_at(deadline, inputs.recv()).await {
                Ok(input) => input,
                Err(_) => {
                    let now = link.now();
                    link.connection.handle_timeout(now);
                    continue;
                }
            },
            None => inputs.recv().await,
        };
        match input {
            Some(ConnectionInput::Datagram(from, bytes)) => {
                let now = link.now();
                link.connection.handle_datagram(now, from, &bytes);
            }
            Some(ConnectionInput::Close) | None => {
                return Err(io::Error::from(io::ErrorKind::ConnectionAborted).to_string());
            }
            // Commands cannot arrive before the swarm knows the connection.
            Some(_) => {}
        }
    }
}
