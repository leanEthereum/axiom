//! The tokio driver: a UDP socket and a clock around the pure service.
//!
//! # Overview
//!
//! 1. A receive task reads the socket and pushes datagrams into the input queue.
//! 2. The handle pushes application commands into the same queue.
//! 3. The driver loop pops each input and feeds it to the service.
//! 4. The loop sends the service's datagrams on the socket.
//! 5. The loop pushes the service's events into the event queue for the application.
//!
//! The loop waits for the next input or the service's next deadline, whichever comes first.
//! Everything else is the service's.

mod command;
mod error;
mod handle;

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use axiom_crypto::secp256k1::SecretKey;
use command::{Command, Input};
pub use error::{DriverStopped, RecordUpdateError};
pub use handle::{Discv5, Discv5Events};
use tokio::{
    net::UdpSocket,
    spawn,
    sync::mpsc,
    time::{Instant, timeout_at},
};

use crate::{
    Csprng,
    enr::Enr,
    packet::MAX_PACKET_LEN,
    service::{Config, Event, Output, Service},
};

/// How long the loop sleeps when the service has no deadline at all.
const IDLE_WAIT: Duration = Duration::from_secs(3600);

/// The loop state: the service and the effects it needs.
struct Driver {
    /// The protocol state machine.
    service: Service,
    /// The socket datagrams go out on.
    socket: Arc<UdpSocket>,
    /// Where events go.
    events: mpsc::UnboundedSender<Event>,
    /// The instant the service's clock counts from.
    start: Instant,
}

impl Driver {
    /// Binds the socket, spawns the reader and the loop, and returns the handle.
    async fn launch(
        key: SecretKey,
        local_enr: Enr,
        config: Config,
        bind: SocketAddr,
    ) -> io::Result<(Discv5, Discv5Events)> {
        // Phase 1: the pure service, seeded from the operating system.
        let service = Service::new(key, local_enr.clone(), config, Csprng::os_seed()?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        let local_addr = socket.local_addr()?;

        // Phase 2: one task reads the socket into the input queue.
        let (input, inputs) = mpsc::unbounded_channel();
        let reader = Arc::clone(&socket);
        let reader_input = input.clone();
        let recv_task = spawn(async move {
            // One byte past the limit lets oversized datagrams reach the decoder and fail there.
            let mut buffer = vec![0_u8; MAX_PACKET_LEN + 1];
            while let Ok((len, from)) = reader.recv_from(&mut buffer).await {
                let datagram = buffer[..len].to_vec();
                if reader_input.send(Input::Datagram(from, datagram)).is_err() {
                    return;
                }
            }
        });

        // Phase 3: the driver loop owns the service.
        let (events, event_stream) = mpsc::unbounded_channel();
        let driver = Self {
            service,
            socket,
            events,
            start: Instant::now(),
        };
        spawn(async move {
            driver.run(inputs).await;
            recv_task.abort();
        });
        Ok((
            Discv5::new(input, local_enr, local_addr),
            Discv5Events::new(event_stream),
        ))
    }

    /// Runs until shutdown or until every handle and the reader are gone.
    async fn run(mut self, mut inputs: mpsc::UnboundedReceiver<Input>) {
        loop {
            // Wait for an input, but no later than the service's next deadline.
            let deadline = self
                .service
                .next_deadline()
                .map_or_else(|| Instant::now() + IDLE_WAIT, |at| self.start + at);
            match timeout_at(deadline, inputs.recv()).await {
                Ok(Some(Input::Datagram(from, bytes))) => {
                    let now = self.start.elapsed();
                    self.service.handle_datagram(now, from, &bytes);
                }
                Ok(None) => return,
                Ok(Some(Input::Command(command))) => {
                    if matches!(*command, Command::Shutdown) {
                        return;
                    }
                    self.command(*command);
                }
                Err(_) => {
                    let now = self.start.elapsed();
                    self.service.handle_timeout(now);
                }
            }
            self.flush().await;
        }
    }

    /// Applies one command to the service.
    fn command(&mut self, command: Command) {
        // Replies go to callers that may have given up; a closed channel is fine.
        let now = self.start.elapsed();
        match command {
            Command::AddEnr(enr, reply) => {
                let _ = reply.send(self.service.add_enr(now, enr));
            }
            Command::Ping(enr, reply) => {
                let _ = reply.send(self.service.ping(now, &enr));
            }
            Command::FindNode(enr, distances, reply) => {
                let _ = reply.send(self.service.find_node(now, &enr, distances));
            }
            Command::TalkRequest {
                enr,
                protocol,
                request,
                reply,
            } => {
                let _ = reply.send(self.service.talk_request(now, &enr, protocol, request));
            }
            Command::TalkResponse {
                node,
                addr,
                request_id,
                response,
            } => self.service.talk_response(node, addr, request_id, response),
            Command::Lookup {
                target,
                filter,
                wanted,
                reply,
            } => {
                let _ = reply.send(self.service.lookup(now, target, filter, wanted));
            }
            Command::SetLocalEnr(enr, reply) => {
                let _ = reply.send(self.service.set_local_enr(enr));
            }
            Command::TableEntries(reply) => {
                let entries = self
                    .service
                    .table()
                    .iter()
                    .map(|entry| entry.enr.clone())
                    .collect();
                let _ = reply.send(entries);
            }
            // Invariant: the loop handles shutdown before dispatching commands.
            Command::Shutdown => {}
        }
    }

    /// Sends every queued datagram and forwards every queued event.
    async fn flush(&mut self) {
        while let Some(output) = self.service.poll_output() {
            match output {
                // UDP is lossy by contract: a failed send is a lost packet.
                Output::Send(datagram) => {
                    let _ = self.socket.send_to(&datagram.bytes, datagram.to).await;
                }
                Output::Event(event) => {
                    let _ = self.events.send(event);
                }
            }
        }
    }
}
