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

use std::{collections::BTreeMap, mem, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::mpsc,
};

use super::{RequestError, RequestId, driver::SwarmInput, upgrade::Upgraded};
use crate::{
    eth::{
        max_compressed_len,
        reqresp::{
            Protocol, ResponseChunk, ResponseCode, ResponseDecoder, decode_request, encode_request,
            encode_response_chunk,
        },
    },
    gossipsub::{ProtocolVersion, Rpc},
    identify::{self, IdentifyInfo},
    identity::PeerId,
    multiaddr::Multiaddr,
    multistream::{Dialer, Listener, Negotiated},
    ping::{self, PingResponder},
    protobuf::{ProtoMessage, encode_length_prefixed, split_length_prefixed},
    secure::{Open, Seal},
    yamux::{self, GoAwayCode, Mode, Session, SessionEvent, StreamId},
};

/// Identifies a connection within the swarm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct ConnectionId(pub(super) u64);

/// Bytes read from the socket per call.
const READ_CHUNK: usize = 64 * 1024;

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
        commands: mpsc::UnboundedSender<ConnectionInput>,
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
    GossipIn(Vec<u8>),
    /// An outbound request reading its response.
    RequestOut(RequestId, Protocol, ResponseDecoder),
    /// An inbound request still arriving.
    RequestIn(Protocol, Vec<u8>),
    /// An inbound request waiting for the node's answer.
    AwaitingResponse,
    /// The outbound identify stream, reading the peer's message.
    IdentifyOut(Vec<u8>),
    /// An inbound ping stream.
    Ping(PingResponder),
}

/// The connection task's state.
struct Connection {
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
    swarm: mpsc::UnboundedSender<SwarmInput>,
    /// Shared settings.
    shared: Arc<Shared>,
    /// The peer's socket address, reported back to it through identify.
    remote_addr: Multiaddr,
    /// Whether the connection should end.
    closing: bool,
}

/// Every protocol this node accepts on inbound streams.
fn supported_protocols() -> Vec<&'static str> {
    let mut protocols: Vec<&'static str> = ProtocolVersion::ALL
        .iter()
        .map(|version| version.protocol_id())
        .collect();
    protocols.extend(Protocol::ALL.iter().map(|protocol| protocol.protocol_id()));
    protocols.push(identify::PROTOCOL);
    protocols.push(ping::PROTOCOL);
    protocols
}

/// Runs a connection after its upgrade, until it closes.
pub(super) async fn run(
    id: ConnectionId,
    upgraded: Upgraded,
    mode: Mode,
    remote_addr: Multiaddr,
    shared: Arc<Shared>,
    swarm: mpsc::UnboundedSender<SwarmInput>,
) {
    let Upgraded {
        tcp,
        session: secure,
        yamux_remainder,
    } = upgraded;
    let (input_tx, mut input_rx) = mpsc::unbounded_channel();
    let peer = secure.remote_peer.clone();
    let _ = swarm.send(SwarmInput::Connection(
        id,
        ConnectionEvent::Established {
            peer,
            commands: input_tx.clone(),
        },
    ));

    // The reader task turns socket bytes into plaintext for this task.
    let (reader, writer) = tcp.into_split();
    let reader_task = tokio::spawn(read_loop(reader, secure.opener, input_tx.clone()));
    if !yamux_remainder.is_empty() {
        let _ = input_tx.send(ConnectionInput::Bytes(yamux_remainder));
    }

    let mut connection = Connection {
        id,
        session: Session::new(mode, shared.yamux),
        sealer: secure.sealer,
        writer,
        streams: BTreeMap::new(),
        gossip_stream: None,
        gossip_queue: Vec::new(),
        swarm,
        shared,
        remote_addr,
        closing: false,
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

    // One input at a time: process, then flush what the session produced.
    while !connection.closing {
        if connection.flush().await.is_err() {
            break;
        }
        let Some(input) = input_rx.recv().await else {
            break;
        };
        connection.handle_input(input);
    }
    // Best effort: tell the peer, then stop reading.
    connection.session.go_away(GoAwayCode::Normal);
    let _ = connection.flush().await;
    let _ = connection.writer.shutdown().await;
    reader_task.abort();
    // Fail requests still in flight.
    for state in mem::take(&mut connection.streams).into_values() {
        if let StreamState::RequestOut(request, ..)
        | StreamState::Dialing(_, Purpose::Request(request, ..)) = state
        {
            connection.report(ConnectionEvent::RequestFailed(
                request,
                RequestError::StreamClosed,
            ));
        }
    }
    connection.report(ConnectionEvent::Closed);
}

/// Reads the socket, unseals, and forwards plaintext until the socket ends.
async fn read_loop(
    mut reader: OwnedReadHalf,
    mut opener: Box<dyn Open>,
    output: mpsc::UnboundedSender<ConnectionInput>,
) {
    let mut buffer = vec![0u8; READ_CHUNK];
    loop {
        let n = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut plaintext = Vec::new();
        if opener.open(&buffer[..n], &mut plaintext).is_err() {
            break;
        }
        if !plaintext.is_empty() && output.send(ConnectionInput::Bytes(plaintext)).is_err() {
            return;
        }
    }
    let _ = output.send(ConnectionInput::Eof);
}

impl Connection {
    /// Reports an event to the swarm.
    fn report(&self, event: ConnectionEvent) {
        let _ = self.swarm.send(SwarmInput::Connection(self.id, event));
    }

    /// Writes everything the session produced, sealed.
    async fn flush(&mut self) -> std::io::Result<()> {
        let plaintext = self.session.take_output();
        if plaintext.is_empty() {
            return Ok(());
        }
        let mut wire = Vec::with_capacity(plaintext.len() + 64);
        self.sealer
            .seal(&plaintext, &mut wire)
            .map_err(std::io::Error::other)?;
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
                None => self.gossip_queue.push(rpc),
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
                    let mut listener = Listener::new(supported_protocols());
                    let _ = self.session.send(stream, &listener.take_output());
                    self.streams
                        .insert(stream, StreamState::Listening(listener));
                }
                SessionEvent::Data { stream, data } => self.on_data(stream, &data),
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
                Ok(Some(negotiated)) => self.dialed(stream, purpose, negotiated),
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
            StreamState::GossipIn(mut buffer) => {
                buffer.extend_from_slice(data);
                self.read_gossip(stream, buffer)
            }
            StreamState::RequestOut(request, protocol, mut decoder) => {
                decoder.feed(data);
                self.read_response(stream, request, protocol, decoder)
            }
            StreamState::RequestIn(protocol, mut buffer) => {
                buffer.extend_from_slice(data);
                // A request can never exceed its framed bound: varint, identifier, compressed body.
                let limit = 10 + 10 + max_compressed_len(*protocol.request_bounds().end()) as usize;
                if buffer.len() > limit {
                    self.answer_error(stream, ResponseCode::InvalidRequest, "request too large");
                    return None;
                }
                Some(StreamState::RequestIn(protocol, buffer))
            }
            StreamState::IdentifyOut(mut buffer) => {
                buffer.extend_from_slice(data);
                // A peer sending far more than one message is broken.
                if buffer.len() > identify::MAX_MESSAGE_LEN + 10 {
                    let _ = self.session.reset(stream);
                    return None;
                }
                Some(StreamState::IdentifyOut(buffer))
            }
            StreamState::Ping(mut responder) => {
                let echo = responder.receive(data);
                let _ = self.session.send(stream, &echo);
                Some(StreamState::Ping(responder))
            }
            // Data on these states is unexpected and dropped.
            state @ (StreamState::GossipOut | StreamState::AwaitingResponse) => Some(state),
        }
    }

    /// Starts the handler of a stream this side opened, once its protocol is agreed.
    fn dialed(
        &mut self,
        stream: StreamId,
        purpose: Purpose,
        negotiated: Negotiated,
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
                    .send(stream, &encode_request(protocol, &payload));
                let _ = self.session.close(stream);
                let mut decoder = ResponseDecoder::new(protocol, self.shared.max_payload_size);
                decoder.feed(&negotiated.remainder);
                self.read_response(stream, request, protocol, decoder)
            }
            Purpose::Identify => {
                // This side only listens on its own identify stream.
                let _ = self.session.close(stream);
                Some(StreamState::IdentifyOut(negotiated.remainder))
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
            return self.read_gossip(stream, remainder);
        }
        if let Some(protocol) = Protocol::from_protocol_id(&protocol) {
            return Some(StreamState::RequestIn(protocol, remainder));
        }
        if protocol == identify::PROTOCOL {
            // Answer with this node's description and the address the peer is seen at.
            let mut info = self.shared.identify.clone();
            info.observed_addr = Some(self.remote_addr.clone());
            let mut bytes = Vec::new();
            encode_length_prefixed(&info, &mut bytes);
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
    fn read_gossip(&mut self, stream: StreamId, mut buffer: Vec<u8>) -> Option<StreamState> {
        loop {
            match split_length_prefixed(&buffer, self.shared.max_gossip_frame) {
                Ok(Some((frame, consumed))) => {
                    match Rpc::decode(frame) {
                        Ok(rpc) => self.report(ConnectionEvent::GossipRpc(rpc)),
                        Err(_) => {
                            let _ = self.session.reset(stream);
                            return None;
                        }
                    }
                    buffer.drain(..consumed);
                }
                Ok(None) => return Some(StreamState::GossipIn(buffer)),
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
            StreamState::RequestIn(protocol, buffer) => {
                // The whole request is in: decode it, or answer with an error.
                match decode_request(protocol, &buffer, self.shared.max_payload_size) {
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
            StreamState::IdentifyOut(buffer) => {
                if let Ok(Some((frame, _))) =
                    split_length_prefixed(&buffer, identify::MAX_MESSAGE_LEN)
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
            | StreamState::GossipOut
            | StreamState::Dialing(..)) => {
                self.streams.insert(stream, state);
            }
        }
    }

    /// Writes response chunks for an inbound request and closes its stream.
    fn respond(&mut self, stream: StreamId, chunks: &[ResponseChunk]) {
        if !matches!(
            self.streams.remove(&stream),
            Some(StreamState::AwaitingResponse)
        ) {
            return;
        }
        let mut bytes = Vec::new();
        for chunk in chunks {
            encode_response_chunk(chunk, &mut bytes);
        }
        let _ = self.session.send(stream, &bytes);
        let _ = self.session.close(stream);
    }

    /// Answers a request with one error chunk and closes the stream.
    fn answer_error(&mut self, stream: StreamId, code: ResponseCode, message: &str) {
        let mut bytes = Vec::new();
        encode_response_chunk(&ResponseChunk::error(code, message), &mut bytes);
        let _ = self.session.send(stream, &bytes);
        let _ = self.session.close(stream);
    }

    /// Writes one gossip RPC as a length-prefixed frame.
    fn write_gossip(&mut self, stream: StreamId, rpc: &Rpc) {
        let mut bytes = Vec::new();
        encode_length_prefixed(rpc, &mut bytes);
        let _ = self.session.send(stream, &bytes);
    }
}
