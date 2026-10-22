//! One connection: a yamux session and the protocol handler of each stream.
//!
//! # Overview
//!
//! Every yamux stream first negotiates its protocol, then runs one handler.
//!
//! ```text
//! stream opened ─▶ multistream-select ─┬─▶ /meshsub/*      length-prefixed RPCs, long-lived
//!                                      ├─▶ /eth2/.../req/  one request, then response chunks
//!                                      ├─▶ /ipfs/id/1.0.0  one identify message
//!                                      └─▶ /ipfs/ping/1.0.0 echo 32-byte probes
//! ```
//!
//! This node opens one gossip stream and one identify stream per connection, and one stream per request.
//!
//! # Backpressure
//!
//! Each turn of the task runs in a fixed order.
//!
//! ```text
//! input ─▶ handlers ─▶ events to the swarm (waits) ─▶ yamux credit ─▶ responses topped up ─▶ socket write
//! ```
//!
//! Credit follows delivery, so a peer can never get further ahead than its receive windows.
//! Responses enter yamux only as fast as its send buffer drains.

use std::{collections::BTreeMap, io, mem, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    spawn,
    sync::mpsc,
    task::JoinHandle,
};

use super::{RequestError, RequestId, driver::SwarmInput, upgrade::Upgraded};
use crate::{
    eth::reqresp::{Protocol, RequestDecoder, ResponseChunk, ResponseCode, ResponseDecoder},
    gossipsub::{ProtocolVersion, Rpc},
    identify::{self, IdentifyInfo},
    identity::PeerId,
    multiaddr::Multiaddr,
    multistream::{Dialer, Listener, Negotiated},
    ping::PingResponder,
    protobuf::{LengthPrefixedDecoder, ProtoMessage},
    secure::{Open, Seal},
    yamux::{self, GoAwayCode, Mode, Session, SessionEvent, StreamId},
};

/// Identifies a connection within the swarm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct ConnectionId(pub(super) u64);

/// Bytes read from the socket per call.
const READ_CHUNK: usize = 64 * 1024;

/// Gossip RPCs held while the gossip stream negotiates; later ones are dropped.
///
/// Threshold: negotiation takes one round trip, far less than a heartbeat of traffic.
const GOSSIP_QUEUE: usize = 64;

/// Settings every connection shares.
#[derive(Debug)]
pub(super) struct Shared {
    /// This node's identify message, without the observed address.
    pub(super) identify: IdentifyInfo,
    /// MAX_PAYLOAD_SIZE.
    pub(super) max_payload_size: u64,
    /// Largest gossip RPC frame.
    pub(super) max_gossip_frame: usize,
    /// Yamux parameters.
    pub(super) yamux: yamux::Config,
    /// Capacity of each connection's input queue.
    pub(super) connection_queue: usize,
}

/// What the connection reports to the swarm.
#[derive(Debug)]
pub(super) enum ConnectionEvent {
    /// The upgrade failed.
    Failed(String),
    /// The upgrade succeeded.
    Established {
        /// The authenticated peer.
        peer: PeerId,
        /// Where to send commands.
        commands: mpsc::Sender<ConnectionInput>,
    },
    /// The outbound gossip stream settled on a protocol revision.
    GossipVersion(ProtocolVersion),
    /// A gossip RPC arrived.
    GossipRpc(Rpc),
    /// A request arrived and awaits a response.
    InboundRequest {
        /// The stream to answer on.
        stream: StreamId,
        /// The method.
        protocol: Protocol,
        /// The decompressed request.
        payload: Vec<u8>,
    },
    /// A response chunk arrived.
    ResponseChunk(RequestId, ResponseChunk),
    /// A response completed.
    ResponseEnded(RequestId),
    /// A request failed.
    RequestFailed(RequestId, RequestError),
    /// The peer identified itself.
    Identified(IdentifyInfo),
    /// The connection is gone.
    Closed,
}

/// What the connection task waits on.
#[derive(Debug)]
pub(super) enum ConnectionInput {
    /// Plaintext from the reader task.
    Bytes(Vec<u8>),
    /// The socket closed or failed.
    Eof,
    /// Send a gossip RPC.
    SendGossip(Rpc),
    /// Open a request stream.
    SendRequest(RequestId, Protocol, Vec<u8>),
    /// Answer a request and close its stream.
    Respond(StreamId, Vec<ResponseChunk>),
    /// Abandon a request.
    CancelRequest(RequestId),
    /// Close the connection.
    Close,
}

/// Why this side opened a stream.
#[derive(Debug)]
enum Purpose {
    /// The gossip stream.
    Gossip,
    /// A request.
    Request(RequestId, Protocol, Vec<u8>),
    /// Asking the peer to identify itself.
    Identify,
}

/// The handler of one stream.
#[derive(Debug)]
enum StreamState {
    /// This side opened the stream and proposes a protocol.
    Dialing(Dialer, Purpose),
    /// The peer opened the stream and proposes.
    Listening(Listener),
    /// The outbound gossip stream, ready for RPCs.
    GossipOut,
    /// An inbound gossip stream, reading RPC frames.
    GossipIn(LengthPrefixedDecoder),
    /// An outbound request reading its response.
    RequestOut(RequestId, Protocol, ResponseDecoder),
    /// An inbound request still arriving.
    RequestIn(RequestDecoder),
    /// An inbound request waiting for the node's answer.
    AwaitingResponse,
    /// Response bytes not yet accepted by the stream's send buffer.
    Responding(Vec<u8>),
    /// The outbound identify stream, reading the peer's message.
    IdentifyOut(LengthPrefixedDecoder),
    /// An inbound ping stream.
    Ping(PingResponder),
}

/// The connection task's state.
pub(super) struct Connection {
    /// This connection's identifier.
    id: ConnectionId,
    /// The yamux session.
    session: Session,
    /// Seals outbound bytes.
    sealer: Box<dyn Seal>,
    /// The socket's write half.
    writer: OwnedWriteHalf,
    /// Stream handlers by stream.
    streams: BTreeMap<StreamId, StreamState>,
    /// The ready outbound gossip stream.
    gossip_stream: Option<StreamId>,
    /// Gossip RPCs queued until the gossip stream is ready.
    gossip_queue: Vec<Rpc>,
    /// The swarm's input.
    swarm: mpsc::Sender<SwarmInput>,
    /// Events produced this turn, delivered before any credit is granted.
    outbox: Vec<ConnectionEvent>,
    /// Data bytes per stream handled this turn, credited once the outbox is delivered.
    credit: Vec<(StreamId, usize)>,
    /// Shared settings.
    shared: Arc<Shared>,
    /// The peer's socket address, reported back to it through identify.
    remote_addr: Multiaddr,
    /// Whether the connection should end.
    closing: bool,
    /// The task reading the socket, stopped when the connection ends.
    _reader: ReaderGuard,
}

impl Connection {
    /// Announces an upgraded connection to the swarm and starts reading its socket.
    ///
    /// # Returns
    ///
    /// The connection and its input queue, or nothing when the swarm has stopped.
    pub(super) async fn establish(
        id: ConnectionId,
        upgraded: Upgraded,
        mode: Mode,
        remote_addr: Multiaddr,
        shared: Arc<Shared>,
        swarm: mpsc::Sender<SwarmInput>,
    ) -> Option<(Self, mpsc::Receiver<ConnectionInput>)> {
        let Upgraded {
            tcp,
            session: secure,
            yamux_remainder,
        } = upgraded;
        let (input_tx, input_rx) = mpsc::channel(shared.connection_queue.max(1));
        let peer = secure.remote_peer.clone();
        let established = SwarmInput::Connection(
            id,
            ConnectionEvent::Established {
                peer,
                commands: input_tx.clone(),
            },
        );
        if swarm.send(established).await.is_err() {
            return None;
        }

        // The reader task turns socket bytes into plaintext for this task.
        // The guard stops it whenever this task ends, even when the swarm aborts it.
        let (reader, writer) = tcp.into_split();
        let reader = SocketReader {
            socket: reader,
            opener: secure.opener,
            output: input_tx,
        };

        let mut connection = Self {
            id,
            session: Session::new(mode, shared.yamux),
            sealer: secure.sealer,
            writer,
            streams: BTreeMap::new(),
            gossip_stream: None,
            gossip_queue: Vec::new(),
            swarm,
            outbox: Vec::new(),
            credit: Vec::new(),
            shared,
            remote_addr,
            closing: false,
            _reader: reader.spawn(),
        };
        // Open the gossip and identify streams at once.
        connection.open(
            Purpose::Gossip,
            &[
                ProtocolVersion::V1_2,
                ProtocolVersion::V1_1,
                ProtocolVersion::V1_0,
            ]
            .map(ProtocolVersion::protocol_id),
        );
        connection.open(Purpose::Identify, &[identify::PROTOCOL]);
        // Plaintext that trailed the multiplexer negotiation comes before anything the reader sees.
        if !yamux_remainder.is_empty() {
            connection.handle_input(ConnectionInput::Bytes(yamux_remainder));
        }
        Some((connection, input_rx))
    }

    /// Runs the connection until it closes.
    pub(super) async fn run(mut self, mut inputs: mpsc::Receiver<ConnectionInput>) {
        // One input at a time, then the turn's fixed sequence.
        loop {
            // Phase 1: hand events to the swarm, waiting while it is busy.
            if self.deliver().await.is_err() {
                break;
            }
            // Phase 2: only now let the peer send more.
            self.grant_credit();
            // Phase 3: move pending responses into whatever send buffer freed up.
            self.pump_responses();
            // Phase 4: write what the session produced.
            if self.flush().await.is_err() || self.closing {
                break;
            }
            let Some(input) = inputs.recv().await else {
                break;
            };
            self.handle_input(input);
        }
        // Best effort: tell the peer, then stop.
        self.session.go_away(GoAwayCode::Normal);
        let _ = self.flush().await;
        let _ = self.writer.shutdown().await;
        // Fail requests still in flight.
        for state in mem::take(&mut self.streams).into_values() {
            if let StreamState::RequestOut(request, ..)
            | StreamState::Dialing(_, Purpose::Request(request, ..)) = state
            {
                self.report(ConnectionEvent::RequestFailed(
                    request,
                    RequestError::StreamClosed,
                ));
            }
        }
        self.report(ConnectionEvent::Closed);
        let _ = self.deliver().await;
    }

    /// Queues an event for the swarm, delivered at the end of the turn.
    fn report(&mut self, event: ConnectionEvent) {
        self.outbox.push(event);
    }

    /// Delivers the turn's events in order, waiting while the swarm queue is full.
    ///
    /// # Errors
    ///
    /// Fails when the swarm has stopped.
    async fn deliver(&mut self) -> Result<(), ()> {
        for event in mem::take(&mut self.outbox) {
            self.swarm
                .send(SwarmInput::Connection(self.id, event))
                .await
                .map_err(|_| ())?;
        }
        Ok(())
    }

    /// Credits the peer for the data this turn handled.
    fn grant_credit(&mut self) {
        for (stream, len) in mem::take(&mut self.credit) {
            self.session.consume(stream, len);
        }
    }

    /// Moves pending response bytes into each stream as its send buffer allows.
    fn pump_responses(&mut self) {
        let responding: Vec<StreamId> = self
            .streams
            .iter()
            .filter(|(_, state)| matches!(state, StreamState::Responding(_)))
            .map(|(stream, _)| *stream)
            .collect();
        for stream in responding {
            let Some(StreamState::Responding(mut bytes)) = self.streams.remove(&stream) else {
                continue;
            };
            // Hand over what fits; a stream that is gone takes nothing and is abandoned.
            let room = self.session.writable(stream).min(bytes.len());
            if room == 0 && !self.session.is_open(stream) {
                continue;
            }
            if room > 0 && self.session.send(stream, &bytes[..room]).is_err() {
                let _ = self.session.reset(stream);
                continue;
            }
            bytes.drain(..room);
            // The last byte is handed over: half-close, and the FIN follows the data.
            if bytes.is_empty() {
                let _ = self.session.close(stream);
            } else {
                self.streams.insert(stream, StreamState::Responding(bytes));
            }
        }
    }

    /// Writes protocol bytes to a stream, resetting it when it cannot take them.
    ///
    /// # Returns
    ///
    /// Whether the stream took the bytes.
    fn write(&mut self, stream: StreamId, bytes: &[u8]) -> bool {
        // A full send buffer means the peer stopped reading this stream.
        if self.session.send(stream, bytes).is_ok() {
            return true;
        }
        let _ = self.session.reset(stream);
        false
    }

    /// Writes everything the session produced, sealed.
    async fn flush(&mut self) -> io::Result<()> {
        let plaintext = self.session.take_output();
        if plaintext.is_empty() {
            return Ok(());
        }
        let mut wire = Vec::with_capacity(plaintext.len() + 64);
        self.sealer
            .seal(&plaintext, &mut wire)
            .map_err(io::Error::other)?;
        self.writer.write_all(&wire).await
    }

    /// Applies one input.
    fn handle_input(&mut self, input: ConnectionInput) {
        match input {
            ConnectionInput::Bytes(bytes) => {
                if self.session.receive(&bytes).is_err() {
                    // The session already queued a go-away with the protocol error code.
                    self.closing = true;
                }
                self.drain_session();
            }
            ConnectionInput::Eof | ConnectionInput::Close => self.closing = true,
            ConnectionInput::SendGossip(rpc) => match self.gossip_stream {
                Some(stream) => self.write_gossip(stream, &rpc),
                // Until the stream is ready, a short queue; gossip beyond it is dropped.
                None if self.gossip_queue.len() < GOSSIP_QUEUE => self.gossip_queue.push(rpc),
                None => {}
            },
            ConnectionInput::SendRequest(request, protocol, payload) => {
                self.open(
                    Purpose::Request(request, protocol, payload),
                    &[protocol.protocol_id()],
                );
            }
            ConnectionInput::Respond(stream, chunks) => self.respond(stream, &chunks),
            ConnectionInput::CancelRequest(request) => {
                let found = self.streams.iter().find_map(|(id, state)| match state {
                    StreamState::RequestOut(r, ..)
                    | StreamState::Dialing(_, Purpose::Request(r, ..))
                        if *r == request =>
                    {
                        Some(*id)
                    }
                    _ => None,
                });
                if let Some(stream) = found {
                    self.streams.remove(&stream);
                    let _ = self.session.reset(stream);
                }
            }
        }
    }

    /// Opens a stream and proposes protocols for a purpose.
    fn open(&mut self, purpose: Purpose, protocols: &[&str]) {
        let opened = self
            .session
            .open_stream()
            .ok()
            .zip(Dialer::new(protocols.iter().copied()).ok());
        let Some((stream, mut dialer)) = opened else {
            // No stream: a request fails at once; gossip and identify are best effort.
            if let Purpose::Request(request, ..) = purpose {
                self.report(ConnectionEvent::RequestFailed(
                    request,
                    RequestError::StreamClosed,
                ));
            }
            return;
        };
        let _ = self.session.send(stream, &dialer.take_output());
        self.streams
            .insert(stream, StreamState::Dialing(dialer, purpose));
    }

    /// Handles every event the session has queued.
    fn drain_session(&mut self) {
        while let Some(event) = self.session.poll_event() {
            match event {
                SessionEvent::InboundStream(stream) => {
                    let mut listener =
                        Listener::new(self.shared.identify.protocols.iter().cloned());
                    let _ = self.session.send(stream, &listener.take_output());
                    self.streams
                        .insert(stream, StreamState::Listening(listener));
                }
                SessionEvent::Data { stream, data } => {
                    // Credit waits until the events this data produces reach the swarm.
                    self.credit.push((stream, data.len()));
                    self.on_data(stream, &data);
                }
                SessionEvent::StreamFinished(stream) => self.on_finished(stream),
                SessionEvent::StreamReset(stream) => {
                    if let Some(
                        StreamState::RequestOut(request, ..)
                        | StreamState::Dialing(_, Purpose::Request(request, ..)),
                    ) = self.streams.remove(&stream)
                    {
                        self.report(ConnectionEvent::RequestFailed(
                            request,
                            RequestError::StreamClosed,
                        ));
                    }
                }
                SessionEvent::GoAway(_) => self.closing = true,
                SessionEvent::Pong(_) => {}
            }
        }
    }

    /// Feeds data to a stream's handler.
    fn on_data(&mut self, stream: StreamId, data: &[u8]) {
        // Take the handler out, so it can use the session freely, and put it back if it lives on.
        let Some(state) = self.streams.remove(&stream) else {
            return;
        };
        if let Some(next) = self.step(stream, state, data) {
            self.streams.insert(stream, next);
        }
    }

    /// Advances one handler with new data, returning its next state, or nothing when done.
    fn step(&mut self, stream: StreamId, state: StreamState, data: &[u8]) -> Option<StreamState> {
        match state {
            StreamState::Dialing(mut dialer, purpose) => match dialer.receive(data) {
                Ok(Some(negotiated)) => self.dialed(stream, purpose, &negotiated),
                Ok(None) => {
                    let _ = self.session.send(stream, &dialer.take_output());
                    Some(StreamState::Dialing(dialer, purpose))
                }
                Err(_) => {
                    // No common protocol, or a broken negotiation.
                    if let Purpose::Request(request, ..) = purpose {
                        self.report(ConnectionEvent::RequestFailed(
                            request,
                            RequestError::Unsupported,
                        ));
                    }
                    let _ = self.session.reset(stream);
                    None
                }
            },
            StreamState::Listening(mut listener) => {
                let outcome = listener.receive(data);
                let _ = self.session.send(stream, &listener.take_output());
                match outcome {
                    Ok(Some(negotiated)) => self.listened(stream, negotiated),
                    Ok(None) => Some(StreamState::Listening(listener)),
                    Err(_) => {
                        let _ = self.session.reset(stream);
                        None
                    }
                }
            }
            StreamState::GossipIn(mut frames) => {
                frames.feed(data);
                self.read_gossip(stream, frames)
            }
            StreamState::RequestOut(request, protocol, mut decoder) => {
                decoder.feed(data);
                self.read_response(stream, request, protocol, decoder)
            }
            StreamState::RequestIn(mut decoder) => {
                // A request can never exceed its framed bound: varint, identifier, compressed body.
                if decoder.feed(data).is_err() {
                    self.answer_error(stream, ResponseCode::InvalidRequest, "request too large");
                    return None;
                }
                Some(StreamState::RequestIn(decoder))
            }
            StreamState::IdentifyOut(mut frames) => {
                frames.feed(data);
                // A peer sending far more than one message is broken.
                if frames.buffered().len() > identify::MAX_MESSAGE_LEN + 10 {
                    let _ = self.session.reset(stream);
                    return None;
                }
                Some(StreamState::IdentifyOut(frames))
            }
            StreamState::Ping(mut responder) => {
                // A peer that pings without reading the echoes loses the stream.
                let echo = responder.receive(data);
                self.write(stream, &echo)
                    .then_some(StreamState::Ping(responder))
            }
            // Data on these states is unexpected and dropped.
            state @ (StreamState::GossipOut
            | StreamState::AwaitingResponse
            | StreamState::Responding(_)) => Some(state),
        }
    }

    /// Starts the handler of a stream this side opened, once its protocol is agreed.
    fn dialed(
        &mut self,
        stream: StreamId,
        purpose: Purpose,
        negotiated: &Negotiated,
    ) -> Option<StreamState> {
        match purpose {
            Purpose::Gossip => {
                let version = ProtocolVersion::from_protocol_id(&negotiated.protocol)
                    .unwrap_or(ProtocolVersion::V1_0);
                self.report(ConnectionEvent::GossipVersion(version));
                self.gossip_stream = Some(stream);
                // Send what queued up while negotiating.
                for rpc in mem::take(&mut self.gossip_queue) {
                    self.write_gossip(stream, &rpc);
                }
                Some(StreamState::GossipOut)
            }
            Purpose::Request(request, protocol, payload) => {
                // Write the request, then half-close: the responder reads until EOF.
                let _ = self
                    .session
                    .send(stream, &protocol.encode_request(&payload));
                let _ = self.session.close(stream);
                let mut decoder = ResponseDecoder::new(protocol, self.shared.max_payload_size);
                decoder.feed(&negotiated.remainder);
                self.read_response(stream, request, protocol, decoder)
            }
            Purpose::Identify => {
                // This side only listens on its own identify stream.
                let _ = self.session.close(stream);
                let mut frames = LengthPrefixedDecoder::new(identify::MAX_MESSAGE_LEN);
                frames.feed(&negotiated.remainder);
                Some(StreamState::IdentifyOut(frames))
            }
        }
    }

    /// Starts the handler of a stream the peer opened, once its protocol is agreed.
    fn listened(&mut self, stream: StreamId, negotiated: Negotiated) -> Option<StreamState> {
        let Negotiated {
            protocol,
            remainder,
        } = negotiated;
        if ProtocolVersion::from_protocol_id(&protocol).is_some() {
            let mut frames = LengthPrefixedDecoder::new(self.shared.max_gossip_frame);
            frames.feed(&remainder);
            return self.read_gossip(stream, frames);
        }
        if let Some(protocol) = Protocol::from_protocol_id(&protocol) {
            let mut decoder = RequestDecoder::new(protocol, self.shared.max_payload_size);
            // The size bound is enforced on the bytes that follow, as they arrive.
            let _ = decoder.feed(&remainder);
            return Some(StreamState::RequestIn(decoder));
        }
        if protocol == identify::PROTOCOL {
            // Answer with this node's description and the address the peer is seen at.
            let mut info = self.shared.identify.clone();
            info.observed_addr = Some(self.remote_addr.clone());
            let mut bytes = Vec::new();
            info.encode_length_prefixed(&mut bytes);
            let _ = self.session.send(stream, &bytes);
            let _ = self.session.close(stream);
            return None;
        }
        // Only ping remains among the supported protocols.
        let mut responder = PingResponder::default();
        let echo = responder.receive(&remainder);
        let _ = self.session.send(stream, &echo);
        Some(StreamState::Ping(responder))
    }

    /// Splits complete gossip frames off a buffer and reports them.
    fn read_gossip(
        &mut self,
        stream: StreamId,
        mut frames: LengthPrefixedDecoder,
    ) -> Option<StreamState> {
        loop {
            match frames.next_frame() {
                Ok(Some(frame)) => match Rpc::decode(frame) {
                    Ok(rpc) => self.report(ConnectionEvent::GossipRpc(rpc)),
                    Err(_) => {
                        let _ = self.session.reset(stream);
                        return None;
                    }
                },
                Ok(None) => return Some(StreamState::GossipIn(frames)),
                Err(_) => {
                    let _ = self.session.reset(stream);
                    return None;
                }
            }
        }
    }

    /// Reports every complete response chunk; ends after an error or a single-chunk answer.
    fn read_response(
        &mut self,
        stream: StreamId,
        request: RequestId,
        protocol: Protocol,
        mut decoder: ResponseDecoder,
    ) -> Option<StreamState> {
        loop {
            match decoder.next_chunk() {
                Ok(Some(chunk)) => {
                    let last =
                        chunk.code != ResponseCode::Success || protocol.has_single_response();
                    self.report(ConnectionEvent::ResponseChunk(request, chunk));
                    if last {
                        self.report(ConnectionEvent::ResponseEnded(request));
                        return None;
                    }
                }
                Ok(None) => return Some(StreamState::RequestOut(request, protocol, decoder)),
                Err(error) => {
                    self.report(ConnectionEvent::RequestFailed(
                        request,
                        RequestError::InvalidResponse(error.to_string()),
                    ));
                    let _ = self.session.reset(stream);
                    return None;
                }
            }
        }
    }

    /// Handles the peer half-closing a stream.
    fn on_finished(&mut self, stream: StreamId) {
        let Some(state) = self.streams.remove(&stream) else {
            return;
        };
        match state {
            StreamState::RequestIn(decoder) => {
                // The whole request is in: take it, or answer with an error.
                let protocol = decoder.protocol();
                match decoder.finish() {
                    Ok(payload) => {
                        self.report(ConnectionEvent::InboundRequest {
                            stream,
                            protocol,
                            payload,
                        });
                        self.streams.insert(stream, StreamState::AwaitingResponse);
                    }
                    Err(error) => {
                        self.answer_error(stream, ResponseCode::InvalidRequest, &error.to_string());
                    }
                }
            }
            StreamState::RequestOut(request, _, mut decoder) => {
                let event = match decoder.finish() {
                    Ok(()) => ConnectionEvent::ResponseEnded(request),
                    Err(error) => ConnectionEvent::RequestFailed(
                        request,
                        RequestError::InvalidResponse(error.to_string()),
                    ),
                };
                self.report(event);
            }
            StreamState::Dialing(_, Purpose::Request(request, ..)) => {
                self.report(ConnectionEvent::RequestFailed(
                    request,
                    RequestError::StreamClosed,
                ));
            }
            StreamState::IdentifyOut(mut frames) => {
                if let Ok(Some(frame)) = frames.next_frame()
                    && let Ok(info) = IdentifyInfo::decode(frame)
                {
                    self.report(ConnectionEvent::Identified(info));
                }
            }
            // The peer stopped writing: close our side too.
            StreamState::GossipIn(_) | StreamState::Ping(_) | StreamState::Listening(_) => {
                let _ = self.session.close(stream);
            }
            // Our side still has something to write; keep the handler.
            state @ (StreamState::AwaitingResponse
            | StreamState::Responding(_)
            | StreamState::GossipOut
            | StreamState::Dialing(..)) => {
                self.streams.insert(stream, state);
            }
        }
    }

    /// Queues response chunks for an inbound request; the stream closes after the last byte.
    fn respond(&mut self, stream: StreamId, chunks: &[ResponseChunk]) {
        if !matches!(
            self.streams.get(&stream),
            Some(StreamState::AwaitingResponse)
        ) {
            return;
        }
        let mut bytes = Vec::new();
        for chunk in chunks {
            chunk.encode_to(&mut bytes);
        }
        // The bytes enter yamux as its send buffer drains, at the end of each turn.
        self.streams.insert(stream, StreamState::Responding(bytes));
    }

    /// Answers a request with one error chunk and closes the stream.
    fn answer_error(&mut self, stream: StreamId, code: ResponseCode, message: &str) {
        let mut bytes = Vec::new();
        ResponseChunk::error(code, message).encode_to(&mut bytes);
        let _ = self.session.send(stream, &bytes);
        let _ = self.session.close(stream);
    }

    /// Writes one gossip RPC as a length-prefixed frame.
    ///
    /// A full send buffer drops the RPC whole, so the frame stream stays well formed.
    fn write_gossip(&mut self, stream: StreamId, rpc: &Rpc) {
        let mut bytes = Vec::new();
        rpc.encode_length_prefixed(&mut bytes);
        let _ = self.session.send(stream, &bytes);
    }
}

/// Reads the socket, unseals, and forwards plaintext to the connection task.
///
/// A failed authentication ends the loop, and with it the connection.
/// A full connection queue makes it wait, so the socket is not read meanwhile.
struct SocketReader {
    /// The socket's read half.
    socket: OwnedReadHalf,
    /// Unseals inbound bytes.
    opener: Box<dyn Open>,
    /// The connection task's input.
    output: mpsc::Sender<ConnectionInput>,
}

impl SocketReader {
    /// Starts reading on a task of its own, stopped when the guard drops.
    fn spawn(self) -> ReaderGuard {
        ReaderGuard(spawn(self.run()))
    }

    /// Forwards plaintext until the socket ends.
    async fn run(mut self) {
        let mut buffer = vec![0u8; READ_CHUNK];
        loop {
            let n = match self.socket.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut plaintext = Vec::new();
            if self.opener.open(&buffer[..n], &mut plaintext).is_err() {
                break;
            }
            if !plaintext.is_empty()
                && self
                    .output
                    .send(ConnectionInput::Bytes(plaintext))
                    .await
                    .is_err()
            {
                return;
            }
        }
        let _ = self.output.send(ConnectionInput::Eof).await;
    }
}

/// Aborts the reader task when dropped.
struct ReaderGuard(JoinHandle<()>);

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        // The reader holds the socket's read half; it must not outlive the connection.
        self.0.abort();
    }
}
