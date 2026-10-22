//! The application's side of a running discovery node.

use std::{io, net::SocketAddr};

use axiom_crypto::secp256k1::SecretKey;
use tokio::sync::{mpsc, oneshot};

use super::{Command, Driver, DriverStopped, Input};
use crate::{
    distance::LogDistance,
    enr::Enr,
    message::RequestId,
    node_id::NodeId,
    service::{Config, EnrFilter, Event, LookupId},
    table::InsertOutcome,
};

/// Controls a running discovery node.
///
/// Requests return at once with their id; answers arrive on the event stream.
#[derive(Clone, Debug)]
pub struct Discv5 {
    /// The driver's input queue.
    input: mpsc::UnboundedSender<Input>,
    /// The local record.
    local_enr: Enr,
    /// The bound socket address.
    local_addr: SocketAddr,
}

/// The stream of events from a running discovery node.
#[derive(Debug)]
pub struct Discv5Events {
    /// The driver's event queue.
    events: mpsc::UnboundedReceiver<Event>,
}

impl Discv5 {
    /// Binds a socket and starts a discovery node on the current tokio runtime.
    ///
    /// # Errors
    ///
    /// Fails when the socket cannot bind, the entropy source cannot be read,
    /// or the record does not belong to the key.
    pub async fn start(
        key: SecretKey,
        local_enr: Enr,
        config: Config,
        bind: SocketAddr,
    ) -> io::Result<(Self, Discv5Events)> {
        Driver::launch(key, local_enr, config, bind).await
    }

    /// A handle over a driver's input queue.
    pub(crate) const fn new(
        input: mpsc::UnboundedSender<Input>,
        local_enr: Enr,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            input,
            local_enr,
            local_addr,
        }
    }

    /// The local record.
    #[must_use]
    pub const fn local_enr(&self) -> &Enr {
        &self.local_enr
    }

    /// The bound socket address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Sends a command and awaits its reply.
    async fn ask<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<T>) -> Command,
    ) -> Result<T, DriverStopped> {
        // A dropped reply channel means the driver stopped mid-command.
        let (reply, answer) = oneshot::channel();
        self.input
            .send(Input::Command(Box::new(command(reply))))
            .map_err(|_| DriverStopped)?;
        answer.await.map_err(|_| DriverStopped)
    }

    /// Adds a known record, such as a boot node.
    ///
    /// # Errors
    ///
    /// Fails when the driver has stopped.
    pub async fn add_enr(&self, enr: Enr) -> Result<InsertOutcome, DriverStopped> {
        self.ask(|reply| Command::AddEnr(enr, reply)).await
    }

    /// Pings a node; the answer arrives as an event.
    ///
    /// # Errors
    ///
    /// Fails when the driver has stopped.
    pub async fn ping(&self, enr: Enr) -> Result<Option<RequestId>, DriverStopped> {
        self.ask(|reply| Command::Ping(enr, reply)).await
    }

    /// Asks a node for records at distances; the answer arrives as an event.
    ///
    /// # Errors
    ///
    /// Fails when the driver has stopped.
    pub async fn find_node(
        &self,
        enr: Enr,
        distances: Vec<LogDistance>,
    ) -> Result<Option<RequestId>, DriverStopped> {
        self.ask(|reply| Command::FindNode(enr, distances, reply))
            .await
    }

    /// Sends an application request; the answer arrives as an event.
    ///
    /// # Errors
    ///
    /// Fails when the driver has stopped.
    pub async fn talk_request(
        &self,
        enr: Enr,
        protocol: Vec<u8>,
        request: Vec<u8>,
    ) -> Result<Option<RequestId>, DriverStopped> {
        self.ask(|reply| Command::TalkRequest {
            enr,
            protocol,
            request,
            reply,
        })
        .await
    }

    /// Answers an application request reported as an event.
    ///
    /// # Errors
    ///
    /// Fails when the driver has stopped.
    pub fn talk_response(
        &self,
        node: NodeId,
        addr: SocketAddr,
        request_id: RequestId,
        response: Vec<u8>,
    ) -> Result<(), DriverStopped> {
        self.input
            .send(Input::Command(Box::new(Command::TalkResponse {
                node,
                addr,
                request_id,
                response,
            })))
            .map_err(|_| DriverStopped)
    }

    /// Starts a lookup; the result arrives as an event.
    ///
    /// # Errors
    ///
    /// Fails when the driver has stopped.
    pub async fn lookup(
        &self,
        target: NodeId,
        filter: EnrFilter,
        wanted: usize,
    ) -> Result<LookupId, DriverStopped> {
        self.ask(|reply| Command::Lookup {
            target,
            filter,
            wanted,
            reply,
        })
        .await
    }

    /// The records in the routing table.
    ///
    /// # Errors
    ///
    /// Fails when the driver has stopped.
    pub async fn table_entries(&self) -> Result<Vec<Enr>, DriverStopped> {
        self.ask(Command::TableEntries).await
    }

    /// Stops the driver and closes its socket.
    pub fn shutdown(&self) {
        // A driver already stopped needs nothing more.
        let _ = self.input.send(Input::Command(Box::new(Command::Shutdown)));
    }
}

impl Discv5Events {
    /// An event stream over a driver's event queue.
    pub(crate) const fn new(events: mpsc::UnboundedReceiver<Event>) -> Self {
        Self { events }
    }

    /// The next event, or nothing once the driver has stopped.
    pub async fn next(&mut self) -> Option<Event> {
        self.events.recv().await
    }
}
