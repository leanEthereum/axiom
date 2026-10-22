//! One QUIC connection: the handshake, packet protection, streams, and recovery together.
//!
//! # Overview
//!
//! The connection is driven from outside, with time as an argument:
//!
//! 1. Datagrams the endpoint routes here go in.
//! 2. Datagrams to send come out, one at a time.
//! 3. A single deadline says when to call back if nothing arrives.
//! 4. Events report the handshake, streams, and the end.
//!
//! The stream calls mirror the yamux session's, so the same stream handlers run over either.
//!
//! # Lifecycle
//!
//! 1. Handshake: CRYPTO frames carry TLS in Initial, then Handshake packets.
//! 2. Established: streams flow in 1-RTT packets.
//! 3. Closing: this side sent CONNECTION_CLOSE and answers further packets with it for three PTOs.
//! 4. Draining: the peer closed; nothing is sent for three PTOs.
//! 5. Closed: the endpoint may forget the connection.
//!
//! This side never migrates and disables migration by the peer.
//! Packets from any address but the peer's are dropped, so a rebound peer reconnects.
//! Stateless reset is not implemented: a peer that lost state is detected by the idle timeout.

mod peer_ids;
mod received;
mod space;

use std::{collections::VecDeque, mem, net::SocketAddr, sync::Arc, time::Duration};

use peer_ids::PeerIds;
use space::PacketSpace;

use super::{
    ConnectionError, ConnectionId, DecodeError, Entropy, Event, QuicConfig, QuicError, Side,
    StreamId, TransportError, TransportErrorCode, VERSION,
    crypto::{InitialSecrets, KeyPair, Keys, OneRttKeys, Protected, RetryTag, TAG_LEN},
    frame::{AckFrame, Frame, FrameIter, PacketKind},
    packet::{Header, LONG_FORM, LongType, PacketNumber, PlainPacket, ProtectedPacket},
    recovery::{Recovery, SentFrame, SentPacket, TimerAction, TimerContext},
    space::Space,
    stream::{StreamRecord, Streams},
    transport_parameters::TransportParameters,
};
use crate::{
    identity::PeerId,
    tls::{Level, TlsOutput, TlsSession},
};

/// Bytes of every connection id this stack issues.
pub(crate) const LOCAL_CID_LEN: usize = 8;

/// The smallest datagram that may carry an Initial packet, per RFC 9000, section 14.1.
const MIN_INITIAL_DATAGRAM: usize = 1200;

/// The amplification factor a server may not exceed before validating the client's address.
const AMPLIFICATION_FACTOR: u64 = 3;

/// Packets held while the keys to open them are not yet available.
///
/// Threshold: one flight of reordered packets; more is dropped and recovered by retransmission.
const MAX_HELD_PACKETS: usize = 16;

/// The ack_delay_exponent this side announces: the default of 3.
const ACK_DELAY_EXPONENT: u32 = 3;

/// The connection ids this side stores for the peer.
const ACTIVE_CONNECTION_ID_LIMIT: u64 = 4;

/// The smallest payload worth a packet of its own.
const MIN_PAYLOAD: usize = 8;

/// A UDP datagram to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// The destination.
    pub destination: SocketAddr,
    /// The UDP payload.
    pub bytes: Vec<u8>,
}

/// The connection's place in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// The handshake runs.
    Handshake,
    /// The handshake completed.
    Established,
    /// This side closed; it answers packets with its close until the deadline.
    Closing {
        /// When the closing period ends.
        until: Duration,
    },
    /// The peer closed; nothing is sent until the deadline.
    Draining {
        /// When the draining period ends.
        until: Duration,
    },
    /// The connection is over.
    Closed,
}

/// The close frame this side sends while closing.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CloseFrame {
    /// The error code.
    code: u64,
    /// The triggering frame type for transport closes; none for application closes.
    frame_type: Option<u64>,
    /// The reason phrase.
    reason: Vec<u8>,
}

/// How far the handshake has come, per RFC 9001, section 4.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Progress {
    /// TLS is still exchanging messages.
    Running,
    /// This side's TLS handshake completed.
    Complete,
    /// The handshake is confirmed, and the Handshake keys are gone.
    Confirmed,
}

/// Control frames owed to the peer, each sent once when due.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Pending {
    /// The server's HANDSHAKE_DONE.
    handshake_done: bool,
    /// A keep-alive PING.
    ping: bool,
    /// The close frame, while closing.
    close: bool,
}

/// What both sides need to start a connection.
#[derive(Clone, Debug)]
pub(crate) struct ConnectionSetup {
    /// Shared settings.
    pub(crate) config: Arc<QuicConfig>,
    /// The id the peer will address this side with.
    pub(crate) local_cid: ConnectionId,
    /// The peer's address.
    pub(crate) remote: SocketAddr,
    /// The connection clock.
    pub(crate) now: Duration,
    /// The wall clock in seconds since the Unix epoch, for certificate validity.
    pub(crate) unix_seconds: u64,
}

/// The client's record of a Retry it obeyed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RetryState {
    /// The token to echo in Initial packets.
    token: Vec<u8>,
    /// The server's id from the Retry, which the server's parameters must echo.
    source_id: ConnectionId,
}

/// One QUIC connection.
#[derive(Debug)]
pub struct Connection {
    /// Which endpoint this side is.
    side: Side,
    /// Shared settings.
    config: Arc<QuicConfig>,
    /// The lifecycle state.
    state: State,
    /// The peer's address.
    remote: SocketAddr,
    /// The id the peer addresses this side with.
    local_cid: ConnectionId,
    /// The ids the peer issued.
    peer_ids: PeerIds,
    /// The client's first destination id, which keys Initial packets.
    original_dcid: ConnectionId,
    /// The peer's source id from its first packet, which its parameters must echo.
    peer_initial_scid: Option<ConnectionId>,
    /// A Retry the client obeyed.
    retry: Option<RetryState>,
    /// The TLS handshake.
    tls: TlsSession,
    /// The peer's transport parameters, once received and validated.
    peer_params: Option<TransportParameters>,
    /// Initial, Handshake and application spaces.
    spaces: [PacketSpace; 3],
    /// The 1-RTT keys.
    one_rtt: Option<OneRttKeys>,
    /// Loss detection and congestion control.
    recovery: Recovery,
    /// The streams.
    streams: Streams,
    /// Events other than stream events, delivered first.
    events: VecDeque<Event>,
    /// The final event, delivered after every stream event.
    closed_event: Option<Event>,
    /// How far the handshake has come.
    handshake: Progress,
    /// Whether the client's address is validated: the server saw a Handshake packet, or the client knows it did.
    validated: bool,
    /// Bytes received from the peer, for the amplification limit.
    bytes_received: u64,
    /// Bytes sent to the peer, for the amplification limit.
    bytes_sent: u64,
    /// When the last packet was processed.
    last_activity: Duration,
    /// When the last ack-eliciting packet was sent.
    last_ack_eliciting_sent: Duration,
    /// Whether sending an ack-eliciting packet restarts the idle timer.
    idle_restart_on_send: bool,
    /// The idle timeout both sides agreed on.
    idle_timeout: Duration,
    /// Control frames owed to the peer.
    pending: Pending,
    /// PATH_CHALLENGE data awaiting an echo.
    path_responses: VecDeque<[u8; 8]>,
    /// The close frame, while closing.
    close_frame: Option<CloseFrame>,
    /// Packets received before their keys, kept for a second try.
    held: Vec<Vec<u8>>,
    /// The latest time the owner reported.
    now: Duration,
}

impl Connection {
    /// Starts a client connection and queues its first flight.
    ///
    /// # Arguments
    ///
    /// - `expected`: the peer this side means to reach, checked against its certificate.
    /// - `entropy`: randomness for the destination id and the TLS secrets.
    pub(crate) fn client(
        setup: ConnectionSetup,
        expected: Option<PeerId>,
        entropy: &mut Entropy,
    ) -> Self {
        // The client's first destination id must be at least 8 random bytes, per RFC 9000, section 7.2.
        let dcid_bytes: [u8; LOCAL_CID_LEN] = entropy.array();
        let dcid = ConnectionId::new(&dcid_bytes).unwrap_or(ConnectionId::EMPTY);
        let mut params = Self::local_parameters(&setup.config);
        params.initial_source_connection_id = Some(setup.local_cid);
        let tls = TlsSession::client(
            Arc::clone(&setup.config.identity),
            params.encode(),
            expected,
            entropy.array(),
            setup.unix_seconds,
        );
        let mut connection = Self::new(Side::Client, setup, dcid, dcid, tls);
        connection.spaces[Space::Initial.index()].keys =
            Some(InitialSecrets::new(&dcid).keys(true));
        connection.drive_tls();
        connection
    }

    /// Accepts a client's first Initial packet and starts the server side.
    ///
    /// # Arguments
    ///
    /// - `original_dcid`: the client's first destination id, which keys Initial packets.
    /// - `client_cid`: the client's source id.
    pub(crate) fn server(
        setup: ConnectionSetup,
        original_dcid: ConnectionId,
        client_cid: ConnectionId,
        entropy: &mut Entropy,
    ) -> Self {
        let mut params = Self::local_parameters(&setup.config);
        params.original_destination_connection_id = Some(original_dcid);
        params.initial_source_connection_id = Some(setup.local_cid);
        let tls = TlsSession::server(
            Arc::clone(&setup.config.identity),
            params.encode(),
            entropy.array(),
            setup.unix_seconds,
        );
        let mut connection = Self::new(Side::Server, setup, client_cid, original_dcid, tls);
        connection.peer_initial_scid = Some(client_cid);
        connection.spaces[Space::Initial.index()].keys =
            Some(InitialSecrets::new(&original_dcid).keys(false));
        connection
    }

    /// The state both constructors share.
    fn new(
        side: Side,
        setup: ConnectionSetup,
        remote_cid: ConnectionId,
        original_dcid: ConnectionId,
        tls: TlsSession,
    ) -> Self {
        let ConnectionSetup {
            config,
            local_cid,
            remote,
            now,
            ..
        } = setup;
        let max_datagram = config.max_datagram as u64;
        let streams = Streams::new(side, config.limits);
        Self {
            side,
            state: State::Handshake,
            remote,
            local_cid,
            peer_ids: PeerIds::new(remote_cid, ACTIVE_CONNECTION_ID_LIMIT),
            original_dcid,
            peer_initial_scid: None,
            retry: None,
            tls,
            peer_params: None,
            spaces: Default::default(),
            one_rtt: None,
            recovery: Recovery::new(max_datagram),
            streams,
            events: VecDeque::new(),
            closed_event: None,
            handshake: Progress::Running,
            validated: false,
            bytes_received: 0,
            bytes_sent: 0,
            last_activity: now,
            last_ack_eliciting_sent: now,
            idle_restart_on_send: true,
            idle_timeout: config.idle_timeout,
            pending: Pending::default(),
            path_responses: VecDeque::new(),
            close_frame: None,
            held: Vec::new(),
            now,
            config,
        }
    }

    /// This side's transport parameters, before the ids each side adds.
    fn local_parameters(config: &QuicConfig) -> TransportParameters {
        let mut params = TransportParameters {
            max_idle_timeout: config.idle_timeout,
            max_udp_payload_size: config.max_datagram as u64,
            max_ack_delay: config.max_ack_delay,
            disable_active_migration: true,
            active_connection_id_limit: ACTIVE_CONNECTION_ID_LIMIT,
            ..TransportParameters::default()
        };
        Streams::new(Side::Client, config.limits).write_parameters(&mut params);
        params
    }

    /// The peer's address.
    #[must_use]
    pub const fn remote(&self) -> SocketAddr {
        self.remote
    }

    /// The id the peer addresses this side with.
    #[must_use]
    pub const fn local_cid(&self) -> ConnectionId {
        self.local_cid
    }

    /// The client's first destination id, which also routes to this connection early on.
    #[must_use]
    pub const fn original_dcid(&self) -> ConnectionId {
        self.original_dcid
    }

    /// Whether the connection is over and may be forgotten.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed)
    }

    /// Whether the handshake completed and streams may open.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.state, State::Established)
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        if let Some(event) = self.events.pop_front() {
            return Some(event);
        }
        if let Some(event) = self.streams.events.pop_front() {
            return Some(event);
        }
        self.closed_event.take()
    }

    // Stream calls, as the yamux session offers them.

    /// Opens a stream.
    pub fn open_stream(&mut self) -> Result<StreamId, QuicError> {
        match self.state {
            State::Established => self.streams.open(),
            State::Handshake => Err(QuicError::NotEstablished),
            _ => Err(QuicError::Closed),
        }
    }

    /// Queues data on a stream.
    pub fn send(&mut self, stream: StreamId, data: &[u8]) -> Result<(), QuicError> {
        self.check_open()?;
        self.streams.send(stream, data)
    }

    /// Bytes a stream accepts before its send buffer is full, or zero when it cannot be written.
    #[must_use]
    pub fn writable(&self, stream: StreamId) -> usize {
        if self.is_established() {
            self.streams.writable(stream)
        } else {
            0
        }
    }

    /// Credits consumed bytes of a stream, so the peer may send more.
    pub fn consume(&mut self, stream: StreamId, len: usize) {
        self.streams.consume(stream, len);
    }

    /// Finishes a stream once its queued data is sent.
    pub fn close(&mut self, stream: StreamId) -> Result<(), QuicError> {
        self.check_open()?;
        self.streams.close(stream)
    }

    /// Aborts a stream in both directions.
    pub fn reset(&mut self, stream: StreamId) -> Result<(), QuicError> {
        self.check_open()?;
        self.streams.reset(stream)
    }

    /// Whether a stream is open in the owner's view.
    #[must_use]
    pub fn is_open(&self, stream: StreamId) -> bool {
        self.is_established() && self.streams.is_open(stream)
    }

    /// Fails unless streams may be used.
    const fn check_open(&self) -> Result<(), QuicError> {
        match self.state {
            State::Established => Ok(()),
            State::Handshake => Err(QuicError::NotEstablished),
            _ => Err(QuicError::Closed),
        }
    }

    /// Closes the connection with an application code.
    pub fn close_connection(&mut self, now: Duration, code: u64, reason: &[u8]) {
        self.now = now;
        if matches!(
            self.state,
            State::Closing { .. } | State::Draining { .. } | State::Closed
        ) {
            return;
        }
        self.enter_closing(
            CloseFrame {
                code,
                frame_type: None,
                reason: reason.to_vec(),
            },
            ConnectionError::LocallyClosed { code },
        );
    }

    /// Starts the closing period with a close frame and the error to report.
    fn enter_closing(&mut self, frame: CloseFrame, error: ConnectionError) {
        let until = self.now + self.recovery.pto() * 3;
        self.state = State::Closing { until };
        self.close_frame = Some(frame);
        self.pending.close = true;
        self.closed_event = Some(Event::Closed(error));
    }

    /// Closes on a transport error this side detected.
    fn fail(&mut self, error: TransportError) {
        if matches!(
            self.state,
            State::Closing { .. } | State::Draining { .. } | State::Closed
        ) {
            return;
        }
        let frame = CloseFrame {
            code: error.code.0,
            frame_type: Some(error.frame_type.unwrap_or(0)),
            reason: error.reason.as_bytes().to_vec(),
        };
        self.enter_closing(frame, ConnectionError::Transport(error));
    }

    /// Ends at once, without a closing period, as an idle timeout or a version mismatch does.
    fn terminate(&mut self, error: ConnectionError) {
        self.state = State::Closed;
        self.closed_event = Some(Event::Closed(error));
    }

    /// The facts that steer the loss detection timer.
    fn timer_context(&self) -> TimerContext {
        let amplification_blocked = self.side == Side::Server
            && !self.validated
            && self.bytes_sent >= AMPLIFICATION_FACTOR * self.bytes_received;
        TimerContext {
            handshake_confirmed: self.handshake == Progress::Confirmed,
            peer_validated: self.side == Side::Server || self.validated,
            has_handshake_keys: self.spaces[Space::Handshake.index()].keys.is_some(),
            amplification_blocked,
        }
    }

    // Receiving.

    /// Takes in a datagram from the peer.
    pub fn handle_datagram(&mut self, now: Duration, from: SocketAddr, datagram: &[u8]) {
        self.now = now;
        if from != self.remote || matches!(self.state, State::Closed | State::Draining { .. }) {
            return;
        }
        self.bytes_received += datagram.len() as u64;
        if let State::Closing { .. } = self.state {
            // Answer with the close again, so a peer that missed it learns.
            self.pending.close = true;
            return;
        }
        let mut rest = datagram;
        while !rest.is_empty() {
            let Ok((packet, next)) = ProtectedPacket::parse(rest, LOCAL_CID_LEN) else {
                // An unparsable packet ends the datagram: nothing after it can be found.
                return;
            };
            rest = next;
            if let Err(error) = self.handle_packet(now, &packet) {
                self.fail(error);
                return;
            }
            if !matches!(self.state, State::Handshake | State::Established) {
                return;
            }
        }
        self.retry_held(now);
    }

    /// Processes one packet; protection failures and duplicates are dropped quietly.
    fn handle_packet(
        &mut self,
        now: Duration,
        packet: &ProtectedPacket<'_>,
    ) -> Result<(), TransportError> {
        match &packet.header {
            Header::VersionNegotiation { versions, .. } => {
                self.on_version_negotiation(versions);
                Ok(())
            }
            Header::Retry {
                scid, token, tag, ..
            } => {
                self.on_retry(packet.bytes, *scid, token, tag);
                Ok(())
            }
            Header::UnsupportedVersion { .. }
            | Header::Long {
                kind: LongType::ZeroRtt | LongType::Retry,
                ..
            } => Ok(()),
            Header::Long {
                kind,
                dcid,
                scid,
                token,
            } => {
                let space = if *kind == LongType::Initial {
                    Space::Initial
                } else {
                    Space::Handshake
                };
                if !self.accepts_dcid(dcid, space) {
                    return Ok(());
                }
                // A server's Initial carries no token, per RFC 9000, section 17.2.2.
                if self.side == Side::Client && space == Space::Initial && !token.is_empty() {
                    return Ok(());
                }
                self.handle_protected(now, packet, space, Some(*scid))
            }
            Header::Short { dcid } => {
                if *dcid != self.local_cid {
                    return Ok(());
                }
                self.handle_protected(now, packet, Space::Data, None)
            }
        }
    }

    /// Whether a long header's destination id belongs to this connection.
    fn accepts_dcid(&self, dcid: &ConnectionId, space: Space) -> bool {
        // Until the client learns the server's id, its Initial packets address the original one.
        *dcid == self.local_cid
            || (self.side == Side::Server && space == Space::Initial && *dcid == self.original_dcid)
    }

    /// Removes protection from a packet and processes its frames.
    fn handle_protected(
        &mut self,
        now: Duration,
        packet: &ProtectedPacket<'_>,
        space: Space,
        scid: Option<ConnectionId>,
    ) -> Result<(), TransportError> {
        if self.spaces[space.index()].discarded {
            return Ok(());
        }
        // Packets whose keys are not ready yet wait; so do 1-RTT packets before the server completes.
        let keys_ready = match space {
            Space::Data => {
                self.one_rtt.is_some()
                    && (self.side == Side::Client || self.handshake >= Progress::Complete)
            }
            _ => self.spaces[space.index()].keys.is_some(),
        };
        if !keys_ready {
            if self.held.len() < MAX_HELD_PACKETS {
                self.held.push(packet.bytes.to_vec());
            }
            return Ok(());
        }
        let mut bytes = packet.bytes.to_vec();
        let Some((number, header_len, payload_len)) =
            self.unprotect(space, &mut bytes, packet.pn_offset, now)
        else {
            return Ok(());
        };
        if self.spaces[space.index()].received.is_duplicate(number) {
            return Ok(());
        }
        // Reserved bits must be zero once protection is off, per RFC 9000, section 17.
        let reserved = if bytes[0] & LONG_FORM == 0 {
            0x18
        } else {
            0x0c
        };
        if bytes[0] & reserved != 0 {
            return Err(TransportError::protocol("reserved header bits are set"));
        }
        self.on_authenticated(space, scid);
        let payload = &bytes[header_len..header_len + payload_len];
        let ack_eliciting = self.handle_frames(now, space, payload)?;
        let max_ack_delay = self.config.max_ack_delay;
        self.spaces[space.index()].received.on_received(
            number,
            ack_eliciting,
            now,
            space != Space::Data,
            max_ack_delay,
        );
        Ok(())
    }

    /// Removes header and packet protection in place.
    ///
    /// # Returns
    ///
    /// The packet number, the header length and the payload length, or nothing when the packet fails to open.
    fn unprotect(
        &mut self,
        space: Space,
        bytes: &mut [u8],
        pn_offset: usize,
        now: Duration,
    ) -> Option<(PacketNumber, usize, usize)> {
        let largest = self.spaces[space.index()].received.largest();
        let retain = self.recovery.pto() * 3;
        let (pn_len, truncated) = match space {
            Space::Data => self
                .one_rtt
                .as_ref()?
                .remote_header
                .unprotect(bytes, pn_offset)
                .ok()?,
            _ => self.spaces[space.index()]
                .keys
                .as_ref()?
                .remote
                .header
                .unprotect(bytes, pn_offset)
                .ok()?,
        };
        let number = PacketNumber::decode(truncated, pn_len, largest);
        let header_len = pn_offset + pn_len;
        let payload_len = bytes.len().checked_sub(header_len + TAG_LEN)?;
        let (header, rest) = bytes.split_at_mut(header_len);
        let (payload, tag) = rest.split_at_mut(payload_len);
        let tag: [u8; TAG_LEN] = (&*tag).try_into().ok()?;
        let opened = match space {
            Space::Data => {
                let phase = header[0] & 0x04 != 0;
                let keys = self.one_rtt.as_mut()?;
                let packet = Protected {
                    header,
                    payload,
                    tag: &tag,
                };
                let opened = keys.open(number, phase, packet, now, retain).is_ok();
                if keys.integrity_exhausted() {
                    self.fail(TransportError::new(
                        TransportErrorCode::AEAD_LIMIT_REACHED,
                        "too many packets failed authentication",
                    ));
                    return None;
                }
                opened
            }
            _ => self.spaces[space.index()]
                .keys
                .as_ref()?
                .remote
                .packet
                .open(number, header, payload, &tag)
                .is_ok(),
        };
        opened.then_some((number, header_len, payload_len))
    }

    /// Bookkeeping for a packet that passed authentication.
    fn on_authenticated(&mut self, space: Space, scid: Option<ConnectionId>) {
        self.last_activity = self.now;
        self.idle_restart_on_send = true;
        match self.side {
            Side::Client => {
                // The server's first packet fixes the id to address it with.
                if self.peer_initial_scid.is_none()
                    && let Some(scid) = scid
                {
                    self.peer_ids.replace_initial(scid);
                    self.peer_initial_scid = Some(scid);
                }
            }
            Side::Server => {
                // A Handshake packet proves the client's address and ends the Initial space.
                if space == Space::Handshake && !self.validated {
                    self.validated = true;
                    self.discard_space(Space::Initial);
                }
            }
        }
    }

    /// Processes a payload's frames, returning whether any elicits an acknowledgment.
    fn handle_frames(
        &mut self,
        now: Duration,
        space: Space,
        payload: &[u8],
    ) -> Result<bool, TransportError> {
        let kind = if space == Space::Data {
            PacketKind::Application
        } else {
            PacketKind::Handshake
        };
        let mut ack_eliciting = false;
        let mut frames = 0;
        for frame in FrameIter::new(payload) {
            let frame = frame?;
            frames += 1;
            if !frame.allowed_in(kind) {
                return Err(TransportError::protocol(format!(
                    "frame type {:#x} in a {space:?} packet",
                    frame.frame_type()
                ))
                .on_frame(frame.frame_type()));
            }
            ack_eliciting |= frame.is_ack_eliciting();
            if self.handle_frame(now, space, &frame)? {
                // The peer closed: the rest of the packet does not matter.
                break;
            }
        }
        if frames == 0 {
            return Err(TransportError::protocol("packet without frames"));
        }
        Ok(ack_eliciting)
    }

    /// Applies one frame, returning true when it closed the connection.
    fn handle_frame(
        &mut self,
        now: Duration,
        space: Space,
        frame: &Frame<'_>,
    ) -> Result<bool, TransportError> {
        let frame_type = frame.frame_type();
        match frame {
            Frame::Padding(_) | Frame::Ping | Frame::PathResponse(_) => {}
            Frame::Ack(ack) => self.handle_ack(now, space, ack)?,
            Frame::Crypto { offset, data } => {
                let ready = self.spaces[space.index()]
                    .on_crypto(*offset, data)
                    .map_err(|error| error.on_frame(frame_type))?;
                if let Some(bytes) = ready {
                    self.tls.read_handshake(space.level(), &bytes)?;
                    self.drive_tls();
                }
            }
            Frame::NewToken(_) => {
                if self.side == Side::Server {
                    return Err(
                        TransportError::protocol("NEW_TOKEN from a client").on_frame(frame_type)
                    );
                }
            }
            Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                id,
                ..
            } => self
                .peer_ids
                .on_new_id(*sequence, *retire_prior_to, *id)
                .map_err(|error| error.on_frame(frame_type))?,
            Frame::RetireConnectionId(sequence) => {
                // Only the handshake id was issued, and it addresses this very packet.
                return Err(TransportError::protocol(format!(
                    "retirement of connection id {sequence}, which cannot be retired"
                ))
                .on_frame(frame_type));
            }
            Frame::PathChallenge(data) => self.path_responses.push_back(*data),
            Frame::Close {
                error_code,
                frame_type: closed_on,
                reason,
            } => {
                let reason = String::from_utf8_lossy(reason).into_owned();
                let error = match closed_on {
                    Some(_) => ConnectionError::PeerTransport {
                        code: TransportErrorCode(*error_code),
                        reason,
                    },
                    None => ConnectionError::PeerApplication {
                        code: *error_code,
                        reason,
                    },
                };
                let until = now + self.recovery.pto() * 3;
                self.state = State::Draining { until };
                self.closed_event = Some(Event::Closed(error));
                return Ok(true);
            }
            Frame::HandshakeDone => {
                if self.side == Side::Server {
                    return Err(TransportError::protocol("HANDSHAKE_DONE from a client")
                        .on_frame(frame_type));
                }
                self.confirm_handshake();
            }
            Frame::ResetStream { .. }
            | Frame::StopSending { .. }
            | Frame::Stream { .. }
            | Frame::MaxData(_)
            | Frame::MaxStreamData { .. }
            | Frame::MaxStreams { .. }
            | Frame::DataBlocked(_)
            | Frame::StreamDataBlocked { .. }
            | Frame::StreamsBlocked { .. } => self.streams.on_frame(frame)?,
        }
        Ok(false)
    }

    /// Applies an acknowledgment to the packets of a space.
    fn handle_ack(
        &mut self,
        now: Duration,
        space: Space,
        ack: &AckFrame,
    ) -> Result<(), TransportError> {
        let exponent = self
            .peer_params
            .as_ref()
            .map_or(3, |params| params.ack_delay_exponent);
        let delay = Duration::from_micros(
            ack.delay
                .checked_shl(u32::try_from(exponent).unwrap_or(u32::MAX))
                .unwrap_or(u64::MAX),
        );
        let context = self.timer_context();
        let outcome = self.recovery.on_ack(space, ack, delay, now, context)?;
        let state = &mut self.spaces[space.index()];
        let largest = PacketNumber(ack.largest());
        state.largest_acked = Some(
            state
                .largest_acked
                .map_or(largest, |acked| acked.max(largest)),
        );
        if space == Space::Handshake {
            self.validated = true;
        }
        if space == Space::Data && !outcome.acked.is_empty() {
            if let Some(keys) = &mut self.one_rtt {
                keys.on_acked(largest);
            }
            // An acknowledged 1-RTT packet confirms the handshake, per RFC 9001, section 4.1.2.
            if self.side == Side::Client {
                self.confirm_handshake();
            }
        }
        for packet in outcome.acked {
            for frame in packet.frames {
                self.on_frame_acked(space, frame);
            }
        }
        for packet in outcome.lost {
            for frame in packet.frames {
                self.on_frame_lost(space, frame);
            }
        }
        Ok(())
    }

    /// Releases what an acknowledged frame held.
    fn on_frame_acked(&mut self, space: Space, frame: SentFrame) {
        match frame {
            SentFrame::Stream(record) => self.streams.on_acked(record),
            SentFrame::Crypto(chunk) => self.spaces[space.index()].crypto_send.on_acked(chunk),
            SentFrame::HandshakeDone | SentFrame::Ping | SentFrame::RetireConnectionId { .. } => {}
        }
    }

    /// Schedules what a lost frame carried for sending again.
    fn on_frame_lost(&mut self, space: Space, frame: SentFrame) {
        match frame {
            SentFrame::Stream(record) => self.streams.on_lost(record),
            SentFrame::Crypto(chunk) => {
                let state = &mut self.spaces[space.index()];
                if !state.discarded {
                    state.crypto_send.on_lost(chunk);
                }
            }
            SentFrame::HandshakeDone => self.pending.handshake_done = true,
            SentFrame::RetireConnectionId { sequence } => {
                self.peer_ids.on_retirement_lost(sequence);
            }
            SentFrame::Ping => {}
        }
    }

    /// Applies everything the TLS session produced.
    fn drive_tls(&mut self) {
        while let Some(output) = self.tls.poll_output() {
            match output {
                TlsOutput::Handshake { level, bytes } => {
                    self.spaces[Space::from_level(level).index()]
                        .crypto_send
                        .write(&bytes);
                }
                TlsOutput::Keys {
                    level: Level::Handshake,
                    secrets,
                } => {
                    self.spaces[Space::Handshake.index()].keys = Some(KeyPair {
                        local: Keys::new(&secrets.local),
                        remote: Keys::new(&secrets.remote),
                    });
                }
                TlsOutput::Keys {
                    level: Level::Application,
                    secrets,
                } => self.one_rtt = Some(OneRttKeys::new(&secrets)),
                TlsOutput::Keys {
                    level: Level::Initial,
                    ..
                } => {}
            }
        }
        if self.peer_params.is_none()
            && let Some(bytes) = self.tls.peer_transport_parameters()
        {
            let bytes = bytes.to_vec();
            if let Err(error) = self.apply_peer_parameters(&bytes) {
                self.fail(error);
                return;
            }
        }
        if self.handshake == Progress::Running && !self.tls.is_handshaking() {
            self.complete_handshake();
        }
    }

    /// Validates and applies the peer's transport parameters, per RFC 9000, section 7.3.
    fn apply_peer_parameters(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        let params = TransportParameters::decode(bytes, self.side.peer())?;
        let mismatch = |what: &str| {
            TransportError::new(
                TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                format!("{what} does not match the packets"),
            )
        };
        if params.initial_source_connection_id != self.peer_initial_scid {
            return Err(mismatch("initial_source_connection_id"));
        }
        if self.side == Side::Client {
            if params.original_destination_connection_id != Some(self.original_dcid) {
                return Err(mismatch("original_destination_connection_id"));
            }
            let retry_source = self.retry.as_ref().map(|retry| retry.source_id);
            if params.retry_source_connection_id != retry_source {
                return Err(mismatch("retry_source_connection_id"));
            }
        }
        self.streams.apply_peer_parameters(&params);
        self.recovery.set_max_ack_delay(params.max_ack_delay);
        if !params.max_idle_timeout.is_zero() {
            self.idle_timeout = self.idle_timeout.min(params.max_idle_timeout);
        }
        self.peer_params = Some(params);
        Ok(())
    }

    /// Marks the TLS handshake complete on this side.
    fn complete_handshake(&mut self) {
        let Some(peer) = self.tls.peer().cloned() else {
            self.fail(TransportError::new(
                TransportErrorCode::crypto(80),
                "handshake completed without an authenticated peer",
            ));
            return;
        };
        if self.peer_params.is_none() {
            self.fail(TransportError::new(
                TransportErrorCode::crypto(109),
                "handshake completed without transport parameters",
            ));
            return;
        }
        self.handshake = Progress::Complete;
        self.state = State::Established;
        self.events.push_back(Event::Connected(peer));
        if self.side == Side::Server {
            // The server confirms at completion and tells the client.
            self.pending.handshake_done = true;
            self.confirm_handshake();
        }
    }

    /// Marks the handshake confirmed and drops the Handshake keys, per RFC 9001, section 4.9.2.
    fn confirm_handshake(&mut self) {
        if self.handshake != Progress::Complete {
            return;
        }
        self.handshake = Progress::Confirmed;
        self.validated = true;
        self.discard_space(Space::Handshake);
    }

    /// Discards a space's keys and the packets in flight in it.
    fn discard_space(&mut self, space: Space) {
        if self.spaces[space.index()].discarded {
            return;
        }
        self.recovery.discard(space);
        self.spaces[space.index()].discard();
    }

    /// Takes in a Version Negotiation packet, as a client that has heard nothing else.
    fn on_version_negotiation(&mut self, versions: &[u32]) {
        // A Version Negotiation listing the version in use is forged or stale, per RFC 9000, section 6.2.
        if self.side == Side::Server
            || self.peer_initial_scid.is_some()
            || versions.contains(&VERSION)
        {
            return;
        }
        self.terminate(ConnectionError::VersionMismatch {
            offered: versions.to_vec(),
        });
    }

    /// Takes in a Retry: a new id, a token, and a fresh start of the Initial flight.
    fn on_retry(&mut self, bytes: &[u8], scid: ConnectionId, token: &[u8], tag: &[u8; 16]) {
        if self.side == Side::Server
            || self.peer_initial_scid.is_some()
            || self.retry.is_some()
            || token.is_empty()
        {
            return;
        }
        let body = &bytes[..bytes.len() - tag.len()];
        if !RetryTag::compute(&self.original_dcid, body).matches(tag) {
            return;
        }
        self.retry = Some(RetryState {
            token: token.to_vec(),
            source_id: scid,
        });
        self.peer_ids.replace_initial(scid);
        // Initial keys now derive from the server's chosen id; the ClientHello goes out again.
        self.spaces[Space::Initial.index()].keys = Some(InitialSecrets::new(&scid).keys(true));
        for packet in self.recovery.discard(Space::Initial) {
            for frame in packet.frames {
                self.on_frame_lost(Space::Initial, frame);
            }
        }
    }

    /// Gives packets held for missing keys another try.
    fn retry_held(&mut self, now: Duration) {
        if self.held.is_empty() {
            return;
        }
        let held = mem::take(&mut self.held);
        for bytes in held {
            let Ok((packet, _)) = ProtectedPacket::parse(&bytes, LOCAL_CID_LEN) else {
                continue;
            };
            if let Err(error) = self.handle_packet(now, &packet) {
                self.fail(error);
                return;
            }
        }
    }

    // Timers.

    /// The next time the owner must call back, if any.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Duration> {
        match self.state {
            State::Closed => return None,
            State::Closing { until } | State::Draining { until } => return Some(until),
            State::Handshake | State::Established => {}
        }
        let mut deadline = self.idle_deadline();
        let mut consider = |time: Option<Duration>| {
            if let Some(time) = time {
                deadline = deadline.min(time);
            }
        };
        consider(self.recovery.timer(self.timer_context(), self.now));
        consider(self.spaces[Space::Data.index()].received.deadline());
        consider(self.keep_alive_deadline());
        Some(deadline)
    }

    /// When the connection times out for silence.
    fn idle_deadline(&self) -> Duration {
        // The timeout is never shorter than three probe timeouts, per RFC 9000, section 10.1.
        let timeout = self.idle_timeout.max(self.recovery.pto() * 3);
        self.last_activity + timeout
    }

    /// When the next keep-alive PING falls due.
    fn keep_alive_deadline(&self) -> Option<Duration> {
        let interval = self.config.keep_alive?;
        self.is_established()
            .then(|| self.last_ack_eliciting_sent.max(self.last_activity) + interval)
    }

    /// Handles the deadline passing.
    pub fn handle_timeout(&mut self, now: Duration) {
        self.now = now;
        match self.state {
            State::Closed => return,
            State::Closing { until } | State::Draining { until } => {
                if now >= until {
                    self.state = State::Closed;
                }
                return;
            }
            State::Handshake | State::Established => {}
        }
        if now >= self.idle_deadline() {
            self.terminate(ConnectionError::TimedOut);
            return;
        }
        let context = self.timer_context();
        if self
            .recovery
            .timer(context, now)
            .is_some_and(|timer| timer <= now)
        {
            match self.recovery.on_timeout(context, now) {
                Some(TimerAction::Lost(space, packets)) => {
                    for packet in packets {
                        for frame in packet.frames {
                            self.on_frame_lost(space, frame);
                        }
                    }
                }
                Some(TimerAction::Probe(space)) => self.schedule_probe(space),
                None => {}
            }
        }
        if self
            .keep_alive_deadline()
            .is_some_and(|deadline| deadline <= now)
        {
            self.pending.ping = true;
        }
    }

    /// Arms two probes in a space and requeues the data of its oldest packets.
    fn schedule_probe(&mut self, space: Space) {
        self.spaces[space.index()].probes = 2;
        let frames: Vec<SentFrame> = self
            .recovery
            .unacked(space)
            .take(2)
            .flat_map(|packet| packet.frames.iter().copied())
            .collect();
        for frame in frames {
            self.on_frame_lost(space, frame);
        }
    }

    // Sending.

    /// The next datagram to send, if any.
    pub fn poll_transmit(&mut self, now: Duration) -> Option<Transmit> {
        self.now = now;
        match self.state {
            State::Closed | State::Draining { .. } => return None,
            State::Closing { .. } => return self.transmit_close(),
            State::Handshake | State::Established => {}
        }
        if let Some(keys) = &mut self.one_rtt
            && keys.confidentiality_exhausted()
        {
            self.fail(TransportError::new(
                TransportErrorCode::AEAD_LIMIT_REACHED,
                "sending key exhausted without an update",
            ));
            return self.transmit_close();
        }
        if let Some(keys) = &mut self.one_rtt {
            keys.update_if_due();
        }
        let mut budget = self.datagram_budget();
        if budget < MIN_PAYLOAD * 4 {
            return None;
        }
        let mut packets: Vec<(PlainPacket, SentPacket)> = Vec::new();
        let mut has_initial = false;
        let mut initial_eliciting = false;
        for space in Space::ALL {
            let Some((plain, sent)) = self.build_packet(space, now, budget) else {
                continue;
            };
            budget -= plain.wire_len();
            if space == Space::Initial {
                has_initial = true;
                initial_eliciting |= sent.ack_eliciting;
            }
            packets.push((plain, sent));
        }
        if packets.is_empty() {
            return None;
        }
        // Datagrams with Initial packets are padded to 1200 bytes, per RFC 9000, section 14.1.
        let pad = has_initial && (self.side == Side::Client || initial_eliciting);
        let total: usize = packets.iter().map(|(plain, _)| plain.wire_len()).sum();
        if pad
            && total < MIN_INITIAL_DATAGRAM
            && let Some((plain, sent)) = packets.last_mut()
        {
            let padding = MIN_INITIAL_DATAGRAM - total;
            plain.payload.resize(plain.payload.len() + padding, 0);
            sent.size += padding as u64;
            sent.in_flight = true;
        }
        let mut bytes = Vec::with_capacity(self.config.max_datagram);
        let mut sent_handshake = false;
        for (plain, mut sent) in packets {
            let space = plain.space;
            let start = bytes.len();
            if self.seal(plain, &mut bytes).is_err() {
                return None;
            }
            sent.size = (bytes.len() - start) as u64;
            if sent.ack_eliciting {
                self.last_ack_eliciting_sent = now;
                if self.idle_restart_on_send {
                    self.last_activity = now;
                    self.idle_restart_on_send = false;
                }
            }
            sent_handshake |= space == Space::Handshake;
            if !sent.frames.is_empty() || sent.ack_eliciting || sent.in_flight {
                self.recovery.on_sent(space, sent);
            }
        }
        // A client discards Initial keys once it sends a Handshake packet, per RFC 9001, section 4.9.1.
        if sent_handshake && self.side == Side::Client {
            self.discard_space(Space::Initial);
        }
        self.bytes_sent += bytes.len() as u64;
        Some(Transmit {
            destination: self.remote,
            bytes,
        })
    }

    /// Bytes the next datagram may take: the size cap, and the server's amplification limit.
    fn datagram_budget(&self) -> usize {
        let peer_max = self
            .peer_params
            .as_ref()
            .map_or(usize::MAX, |params| params.max_udp_payload_size as usize);
        let mut budget = self.config.max_datagram.min(peer_max);
        if self.side == Side::Server && !self.validated {
            let allowance =
                (AMPLIFICATION_FACTOR * self.bytes_received).saturating_sub(self.bytes_sent);
            budget = budget.min(usize::try_from(allowance).unwrap_or(usize::MAX));
        }
        budget
    }

    /// Seals a packet into a datagram with its space's keys.
    fn seal(&mut self, plain: PlainPacket, out: &mut Vec<u8>) -> Result<(), DecodeError> {
        match plain.space {
            Space::Data => match &mut self.one_rtt {
                Some(keys) => keys.seal_packet(plain, out),
                None => Ok(()),
            },
            space => match &self.spaces[space.index()].keys {
                Some(keys) => plain.seal(
                    |number, header, payload| keys.local.packet.seal(number, header, payload),
                    &keys.local.header,
                    out,
                ),
                None => Ok(()),
            },
        }
    }

    /// Builds the next packet of a space within a size, if it has anything to say.
    fn build_packet(
        &mut self,
        space: Space,
        now: Duration,
        room: usize,
    ) -> Option<(PlainPacket, SentPacket)> {
        let can_send = match space {
            Space::Data => self.one_rtt.is_some() && self.handshake >= Progress::Complete,
            _ => self.spaces[space.index()].can_send(),
        };
        if !can_send {
            return None;
        }
        let state = &self.spaces[space.index()];
        let number = state.next_number;
        let mut plain = match space {
            Space::Data => {
                let phase = self.one_rtt.as_ref().is_some_and(OneRttKeys::phase);
                PlainPacket::short(&self.peer_ids.current(), phase, number, state.largest_acked)
            }
            _ => {
                let kind = if space == Space::Initial {
                    LongType::Initial
                } else {
                    LongType::Handshake
                };
                let token = self.retry.as_ref().map_or(&[][..], |retry| &retry.token);
                PlainPacket::long(
                    kind,
                    &self.peer_ids.current(),
                    &self.local_cid,
                    token,
                    number,
                    state.largest_acked,
                )
            }
        };
        let max = room.checked_sub(plain.overhead())?;
        if max < MIN_PAYLOAD {
            return None;
        }
        let mut frames = Vec::new();
        let mut ack_eliciting = false;
        let has_more = self.has_eliciting(space);
        let probing = self.spaces[space.index()].probes > 0;

        // 1. The acknowledgment, when due or when it can ride along.
        let received = &mut self.spaces[space.index()].received;
        // Initial and Handshake acknowledgments go out at once, so their delay field is unscaled.
        let exponent = if space == Space::Data {
            ACK_DELAY_EXPONENT
        } else {
            0
        };
        if (received.ack_due(now) || (has_more && received.can_piggyback()))
            && let Some(ack) = received.take_ack(now, exponent)
        {
            Frame::Ack(ack).encode(&mut plain.payload);
        }

        // 2. Everything else, within the congestion window unless probing.
        let window = if probing {
            usize::MAX
        } else {
            usize::try_from(self.recovery.congestion.available()).unwrap_or(usize::MAX)
        };
        let limit = max.min(
            window
                .saturating_sub(plain.overhead())
                .max(plain.payload.len()),
        );
        if has_more && limit > plain.payload.len() + MIN_PAYLOAD {
            ack_eliciting |= self.write_frames(space, &mut plain.payload, limit, &mut frames);
        }
        if probing && !ack_eliciting {
            Frame::Ping.encode(&mut plain.payload);
            frames.push(SentFrame::Ping);
            ack_eliciting = true;
        }
        if plain.payload.is_empty() {
            return None;
        }
        let state = &mut self.spaces[space.index()];
        if ack_eliciting && state.probes > 0 {
            state.probes -= 1;
        }
        let number = state.take_number();
        plain.pad_for_sample();
        let sent = SentPacket {
            number,
            time_sent: now,
            size: plain.wire_len() as u64,
            ack_eliciting,
            in_flight: ack_eliciting,
            frames,
        };
        Some((plain, sent))
    }

    /// Whether a space has ack-eliciting frames to send.
    fn has_eliciting(&self, space: Space) -> bool {
        let state = &self.spaces[space.index()];
        let crypto = state.crypto_send.has_pending(u64::MAX);
        if space != Space::Data {
            return crypto || state.probes > 0;
        }
        crypto
            || state.probes > 0
            || self.pending.ping
            || self.pending.handshake_done
            || !self.path_responses.is_empty()
            || self.peer_ids.has_retirements()
            || self.streams.has_pending()
    }

    /// Writes a space's ack-eliciting frames into a payload, returning whether any was written.
    fn write_frames(
        &mut self,
        space: Space,
        out: &mut Vec<u8>,
        max: usize,
        frames: &mut Vec<SentFrame>,
    ) -> bool {
        let start = out.len();
        if space == Space::Data {
            if self.pending.handshake_done && out.len() < max {
                self.pending.handshake_done = false;
                Frame::HandshakeDone.encode(out);
                frames.push(SentFrame::HandshakeDone);
            }
            while out.len() + 9 <= max
                && let Some(data) = self.path_responses.pop_front()
            {
                Frame::PathResponse(data).encode(out);
            }
            for sequence in self.peer_ids.take_retirements() {
                Frame::RetireConnectionId(sequence).encode(out);
                frames.push(SentFrame::RetireConnectionId { sequence });
            }
        }
        // Handshake bytes, as many frames as fit.
        let crypto = &mut self.spaces[space.index()].crypto_send;
        loop {
            let header = Frame::crypto_header_len(crypto.sent_end().max(1 << 20), max);
            if out.len() + header >= max {
                break;
            }
            let Some(chunk) = crypto.next_chunk(max - out.len() - header, u64::MAX) else {
                break;
            };
            let mut data = Vec::with_capacity(chunk.len);
            crypto.copy(chunk, &mut data);
            Frame::Crypto {
                offset: chunk.offset,
                data: &data,
            }
            .encode(out);
            frames.push(SentFrame::Crypto(chunk));
        }
        if space == Space::Data {
            let mut records: Vec<StreamRecord> = Vec::new();
            self.streams.write(out, max, &mut records);
            frames.extend(records.into_iter().map(SentFrame::Stream));
            if self.pending.ping {
                self.pending.ping = false;
                if out.len() == start && out.len() < max {
                    Frame::Ping.encode(out);
                    frames.push(SentFrame::Ping);
                }
            }
        }
        out.len() > start
    }

    /// The close packets, while closing: one per space with keys.
    fn transmit_close(&mut self) -> Option<Transmit> {
        if !self.pending.close {
            return None;
        }
        self.pending.close = false;
        let frame = self.close_frame.clone()?;
        let mut bytes = Vec::new();
        let budget = self.datagram_budget().max(MIN_INITIAL_DATAGRAM);
        let mut has_initial = false;
        let mut plains = Vec::new();
        for space in Space::ALL {
            let can_send = match space {
                Space::Data => self.one_rtt.is_some() && self.handshake >= Progress::Complete,
                _ => self.spaces[space.index()].can_send(),
            };
            if !can_send {
                continue;
            }
            let state = &mut self.spaces[space.index()];
            let number = state.take_number();
            let mut plain = match space {
                Space::Data => PlainPacket::short(
                    &self.peer_ids.current(),
                    self.one_rtt.as_ref().is_some_and(OneRttKeys::phase),
                    number,
                    state.largest_acked,
                ),
                _ => {
                    has_initial |= space == Space::Initial;
                    let kind = if space == Space::Initial {
                        LongType::Initial
                    } else {
                        LongType::Handshake
                    };
                    let token = self.retry.as_ref().map_or(&[][..], |retry| &retry.token);
                    PlainPacket::long(
                        kind,
                        &self.peer_ids.current(),
                        &self.local_cid,
                        token,
                        number,
                        state.largest_acked,
                    )
                }
            };
            // An application close in a handshake packet would leak the reason: send a bare APPLICATION_ERROR.
            let close = match (&frame.frame_type, space) {
                (None, Space::Initial | Space::Handshake) => Frame::Close {
                    error_code: TransportErrorCode::APPLICATION_ERROR.0,
                    frame_type: Some(0),
                    reason: &[],
                },
                _ => Frame::Close {
                    error_code: frame.code,
                    frame_type: frame.frame_type,
                    reason: &frame.reason[..frame.reason.len().min(budget / 4)],
                },
            };
            close.encode(&mut plain.payload);
            plains.push(plain);
        }
        let total: usize = plains.iter().map(PlainPacket::wire_len).sum();
        if has_initial
            && self.side == Side::Client
            && total < MIN_INITIAL_DATAGRAM
            && let Some(last) = plains.last_mut()
        {
            last.payload
                .resize(last.payload.len() + MIN_INITIAL_DATAGRAM - total, 0);
        }
        for plain in plains {
            self.seal(plain, &mut bytes).ok()?;
        }
        if bytes.is_empty() {
            return None;
        }
        self.bytes_sent += bytes.len() as u64;
        Some(Transmit {
            destination: self.remote,
            bytes,
        })
    }

    /// Starts a 1-RTT key update, if the rules allow one now.
    pub fn update_keys(&mut self) -> bool {
        self.handshake == Progress::Confirmed
            && self.one_rtt.as_mut().is_some_and(OneRttKeys::force_update)
    }
}
