//! The session state machine: framing, stream lifecycle, and flow control.

use std::{
    collections::{BTreeMap, VecDeque},
    mem,
};

use super::{
    Config, Flags, FrameType, GoAwayCode, Header, INITIAL_WINDOW, StreamId, YamuxError,
    reader::FrameReader,
};

/// Which end of the underlying connection this session is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The dialer, which opens odd stream identifiers.
    Client,
    /// The listener, which opens even stream identifiers.
    Server,
}

/// Something the peer did, reported to the owner of the session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// The peer opened a stream.
    InboundStream(StreamId),
    /// Data arrived on a stream.
    Data {
        /// The stream.
        stream: StreamId,
        /// The bytes, in order.
        data: Vec<u8>,
    },
    /// The peer half-closed a stream: no more data will arrive on it.
    StreamFinished(StreamId),
    /// The peer aborted a stream.
    StreamReset(StreamId),
    /// The peer answered a ping.
    Pong(u32),
    /// The peer is shutting the session down.
    GoAway(GoAwayCode),
}

/// Progress of one side's half-close of a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteState {
    /// The owner may still write.
    Open,
    /// The owner closed, but queued data must drain before the FIN.
    Closing,
    /// The FIN frame is written.
    Closed,
}

/// The state of one open stream.
#[derive(Clone, Debug)]
struct Stream {
    /// Bytes the peer still accepts before it grants more credit.
    send_window: u32,
    /// Bytes the peer may still send before this side grants more credit.
    recv_window: u32,
    /// Bytes received but not yet consumed by the owner.
    unconsumed: u32,
    /// Bytes consumed since the last credit was granted.
    consumed: u32,
    /// Bytes written by the owner but held back by the send window.
    pending: VecDeque<u8>,
    /// Flags owed to the peer on the next frame: SYN when opening, ACK when accepting.
    owed_flags: Flags,
    /// Progress of this side's half-close.
    write: WriteState,
    /// Whether the peer closed its write side.
    remote_closed: bool,
    /// Whether this side opened the stream and the peer has not acknowledged it yet.
    awaiting_ack: bool,
}

impl Stream {
    /// A fresh stream with the windows both sides assume.
    const fn new(owed_flags: Flags, awaiting_ack: bool) -> Self {
        Self {
            send_window: INITIAL_WINDOW,
            recv_window: INITIAL_WINDOW,
            unconsumed: 0,
            consumed: 0,
            pending: VecDeque::new(),
            owed_flags,
            write: WriteState::Open,
            remote_closed: false,
            awaiting_ack,
        }
    }

    /// Whether both directions are finished, so the stream can be forgotten.
    const fn is_done(&self) -> bool {
        matches!(self.write, WriteState::Closed) && self.remote_closed
    }
}

/// A yamux session, driven by bytes in and bytes out.
///
/// # Overview
///
/// The owner feeds bytes read from the connection and drains bytes to write.
/// Stream operations queue frames, and peer actions queue events.
/// Nothing here blocks, reads a clock, or touches a socket.
///
/// Received data is credited back to the peer only once the owner reports it consumed.
/// A slow owner therefore stalls the peer at the receive window.
/// Outbound data held back by the peer's window is capped per stream.
#[derive(Debug)]
pub struct Session {
    /// Which identifier parity this side opens.
    mode: Mode,
    /// Tunables.
    config: Config,
    /// Open streams by identifier.
    streams: BTreeMap<StreamId, Stream>,
    /// The identifier the next outbound stream takes.
    next_id: u32,
    /// Outbound streams the peer has not yet acknowledged.
    ack_backlog: usize,
    /// Splits frames off the bytes received.
    inbound: FrameReader,
    /// Encoded frames waiting to be written.
    outbound: Vec<u8>,
    /// Events waiting for the owner.
    events: VecDeque<SessionEvent>,
    /// Whether either side announced a go-away.
    closing: bool,
}

impl Session {
    /// A session for one end of a connection.
    #[must_use]
    pub const fn new(mode: Mode, config: Config) -> Self {
        Self {
            mode,
            config,
            streams: BTreeMap::new(),
            // Clients open 1, 3, 5, ...; servers open 2, 4, 6, ...
            next_id: match mode {
                Mode::Client => 1,
                Mode::Server => 2,
            },
            ack_backlog: 0,
            inbound: FrameReader::new(),
            outbound: Vec::new(),
            events: VecDeque::new(),
            closing: false,
        }
    }

    /// Takes the bytes to write to the connection.
    pub fn take_output(&mut self) -> Vec<u8> {
        mem::take(&mut self.outbound)
    }

    /// The next event for the owner.
    pub fn poll_event(&mut self) -> Option<SessionEvent> {
        self.events.pop_front()
    }

    /// Whether a stream is open in at least one direction.
    #[must_use]
    pub fn is_open(&self, stream: StreamId) -> bool {
        self.streams.contains_key(&stream)
    }

    /// Number of open streams.
    #[must_use]
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Opens an outbound stream.
    ///
    /// The SYN leaves at once, so the peer learns of the stream even before data flows.
    pub fn open_stream(&mut self) -> Result<StreamId, YamuxError> {
        // A session that is going away accepts no new streams.
        if self.closing {
            return Err(YamuxError::SessionClosing);
        }
        // The specification's only backpressure on stream creation.
        if self.ack_backlog >= self.config.max_ack_backlog {
            return Err(YamuxError::AckBacklogFull);
        }
        let id = StreamId(self.next_id);
        // Identifiers grow by two to keep their parity; at the top they are spent.
        self.next_id = self
            .next_id
            .checked_add(2)
            .ok_or(YamuxError::StreamIdsExhausted)?;
        self.ack_backlog += 1;
        self.streams.insert(id, Stream::new(Flags::SYN, true));
        self.announce(id);
        Ok(id)
    }

    /// Queues data on a stream, sending what the window allows right away.
    ///
    /// # Errors
    ///
    /// Fails when the stream is not open for writing, or its send buffer is full.
    pub fn send(&mut self, id: StreamId, data: &[u8]) -> Result<(), YamuxError> {
        let max_send_buffer = self.config.max_send_buffer;
        let stream = self
            .streams
            .get_mut(&id)
            .ok_or(YamuxError::UnknownStream(id))?;
        if !matches!(stream.write, WriteState::Open) {
            return Err(YamuxError::StreamClosed(id));
        }
        // Threshold: an idle stream takes any write; a backed-up one only up to the cap.
        if !stream.pending.is_empty() && stream.pending.len() + data.len() > max_send_buffer {
            return Err(YamuxError::SendBufferFull(id));
        }
        stream.pending.extend(data);
        self.flush_stream(id);
        Ok(())
    }

    /// Bytes a stream accepts before its send buffer is full, or zero when it cannot be written.
    #[must_use]
    pub fn writable(&self, id: StreamId) -> usize {
        self.streams
            .get(&id)
            .filter(|stream| matches!(stream.write, WriteState::Open))
            .map_or(0, |stream| {
                self.config
                    .max_send_buffer
                    .saturating_sub(stream.pending.len())
            })
    }

    /// Reports that the owner consumed bytes of a stream's data, so the peer may send more.
    ///
    /// Credit is granted in batches of half a window.
    /// Bytes beyond those received and not yet consumed are ignored.
    pub fn consume(&mut self, id: StreamId, len: usize) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        // Never credit more than the peer actually sent.
        let len = u32::try_from(len)
            .unwrap_or(u32::MAX)
            .min(stream.unconsumed);
        stream.unconsumed -= len;
        stream.consumed += len;
        self.grant_credit(id);
    }

    /// Half-closes a stream once its queued data has been sent.
    pub fn close(&mut self, id: StreamId) -> Result<(), YamuxError> {
        let stream = self
            .streams
            .get_mut(&id)
            .ok_or(YamuxError::UnknownStream(id))?;
        // Closing twice is harmless: a sent FIN stays sent.
        if matches!(stream.write, WriteState::Open) {
            stream.write = WriteState::Closing;
        }
        self.flush_stream(id);
        Ok(())
    }

    /// Aborts a stream at once, dropping any queued data.
    pub fn reset(&mut self, id: StreamId) -> Result<(), YamuxError> {
        let stream = self
            .streams
            .remove(&id)
            .ok_or(YamuxError::UnknownStream(id))?;
        // An unacknowledged stream no longer counts against the backlog.
        if stream.awaiting_ack {
            self.ack_backlog -= 1;
        }
        self.write_frame(FrameType::WindowUpdate, Flags::RST, id, 0, &[]);
        Ok(())
    }

    /// Sends a ping carrying an opaque value the peer echoes back.
    pub fn ping(&mut self, opaque: u32) {
        self.write_frame(FrameType::Ping, Flags::SYN, StreamId::SESSION, opaque, &[]);
    }

    /// Announces that this side opens no new streams and is shutting down.
    pub fn go_away(&mut self, code: GoAwayCode) {
        self.closing = true;
        self.write_frame(
            FrameType::GoAway,
            Flags::NONE,
            StreamId::SESSION,
            code.code(),
            &[],
        );
    }

    /// Feeds bytes read from the connection.
    ///
    /// # Errors
    ///
    /// A protocol violation is fatal.
    /// A go-away with the protocol error code is queued before the error returns.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<(), YamuxError> {
        self.inbound.feed(bytes);
        let result = loop {
            match self.handle_frame() {
                Ok(true) => {}
                Ok(false) => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        if result.is_err() {
            self.go_away(GoAwayCode::ProtocolError);
        }
        result
    }

    /// Handles the next frame, returning whether there was a complete one.
    fn handle_frame(&mut self) -> Result<bool, YamuxError> {
        // Phase 1: wait for the full 12-byte header.
        let Some(header) = self.inbound.header()? else {
            return Ok(false);
        };

        // Phase 2: dispatch on type; only data frames carry a body.
        match header.frame_type {
            FrameType::Data => {
                // Check the window before buffering, so a peer cannot make us hold a huge body.
                self.check_window(&header)?;
                let Some(body) = self.inbound.body(&header) else {
                    return Ok(false);
                };
                let body = body.to_vec();
                self.on_stream_frame(header, body)?;
            }
            FrameType::WindowUpdate => self.on_stream_frame(header, Vec::new())?,
            FrameType::Ping => {
                // A request is echoed with ACK; a response is reported.
                if header.flags.contains(Flags::SYN) {
                    self.write_frame(
                        FrameType::Ping,
                        Flags::ACK,
                        StreamId::SESSION,
                        header.length,
                        &[],
                    );
                } else if header.flags.contains(Flags::ACK) {
                    self.events.push_back(SessionEvent::Pong(header.length));
                }
            }
            FrameType::GoAway => {
                self.closing = true;
                self.events
                    .push_back(SessionEvent::GoAway(GoAwayCode::from_code(header.length)));
            }
        }
        // Only a frame handled without error leaves the buffer.
        self.inbound.consume(&header);
        Ok(true)
    }

    /// Rejects a data frame larger than the window left on its stream.
    fn check_window(&self, header: &Header) -> Result<(), YamuxError> {
        // An unknown stream, or one being opened, has the window granted at open.
        let window = self
            .streams
            .get(&header.stream_id)
            .map_or(self.config.receive_window, |stream| stream.recv_window);
        if header.length > window {
            return Err(YamuxError::WindowExceeded {
                stream: header.stream_id,
                len: header.length,
                window,
            });
        }
        Ok(())
    }

    /// Applies a data or window update frame to its stream.
    fn on_stream_frame(&mut self, header: Header, body: Vec<u8>) -> Result<(), YamuxError> {
        let id = header.stream_id;
        // Stream frames never address the session.
        if id == StreamId::SESSION {
            return Err(YamuxError::InvalidStreamId(id));
        }

        // Phase 1: a SYN opens a stream from the peer.
        if header.flags.contains(Flags::SYN) {
            self.accept_stream(id)?;
        }

        // A frame for a stream already forgotten is a late straggler: ignore it.
        let Some(stream) = self.streams.get_mut(&id) else {
            return Ok(());
        };

        // Phase 2: an ACK settles one of our openings.
        if header.flags.contains(Flags::ACK) && stream.awaiting_ack {
            stream.awaiting_ack = false;
            self.ack_backlog -= 1;
        }

        // Phase 3: RST aborts at once; nothing else in the frame matters.
        if header.flags.contains(Flags::RST) {
            let stream = self.streams.remove(&id);
            if stream.is_some_and(|stream| stream.awaiting_ack) {
                self.ack_backlog -= 1;
            }
            self.events.push_back(SessionEvent::StreamReset(id));
            return Ok(());
        }

        // Phase 4: the type-specific part.
        match header.frame_type {
            FrameType::WindowUpdate => {
                // Credit grows the send window, then held-back data may flow.
                stream.send_window = stream
                    .send_window
                    .checked_add(header.length)
                    .ok_or(YamuxError::WindowOverflow(id))?;
                self.flush_stream(id);
            }
            _ => {
                // Invariant: the window check ran before the body was buffered.
                stream.recv_window -= header.length;
                // Credit waits until the owner consumes the bytes.
                stream.unconsumed += header.length;
                if !body.is_empty() {
                    self.events.push_back(SessionEvent::Data {
                        stream: id,
                        data: body,
                    });
                }
            }
        }

        // Phase 5: FIN half-closes the peer's direction.
        if header.flags.contains(Flags::FIN) {
            if let Some(stream) = self.streams.get_mut(&id) {
                stream.remote_closed = true;
            }
            self.events.push_back(SessionEvent::StreamFinished(id));
            self.forget_if_done(id);
        }
        Ok(())
    }

    /// Registers a stream the peer opened, or refuses it.
    fn accept_stream(&mut self, id: StreamId) -> Result<(), YamuxError> {
        // The peer must use the opposite parity: odd for a client peer.
        //
        //     we are server → peer is client → peer ids are odd
        let peer_parity = match self.mode {
            Mode::Server => 1,
            Mode::Client => 0,
        };
        if id.0 % 2 != peer_parity {
            return Err(YamuxError::InvalidStreamId(id));
        }
        if self.streams.contains_key(&id) {
            return Err(YamuxError::DuplicateStream(id));
        }
        // Over capacity or closing: refuse politely with RST instead of failing the session.
        if self.closing || self.streams.len() >= self.config.max_streams {
            self.write_frame(FrameType::WindowUpdate, Flags::RST, id, 0, &[]);
            return Ok(());
        }
        self.streams.insert(id, Stream::new(Flags::ACK, false));
        self.events.push_back(SessionEvent::InboundStream(id));
        // Acknowledge immediately, announcing any window above the default.
        self.announce(id);
        Ok(())
    }

    /// Sends the SYN or ACK a stream owes, with the extra window this side grants.
    fn announce(&mut self, id: StreamId) {
        let extra = self.config.receive_window.saturating_sub(INITIAL_WINDOW);
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        // The granted window takes effect for the peer once it reads this frame.
        stream.recv_window += extra;
        let flags = mem::take(&mut stream.owed_flags);
        self.write_frame(FrameType::WindowUpdate, flags, id, extra, &[]);
    }

    /// Grants the peer fresh credit once the owner has consumed half the window.
    fn grant_credit(&mut self, id: StreamId) {
        let threshold = self.config.receive_window / 2;
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        // Batching credit halves the number of window updates on a busy stream.
        //
        //     window 256 KiB → one update per 128 KiB received
        if stream.consumed < threshold || stream.remote_closed {
            return;
        }
        let credit = mem::take(&mut stream.consumed);
        stream.recv_window += credit;
        self.write_frame(FrameType::WindowUpdate, Flags::NONE, id, credit, &[]);
    }

    /// Writes as much queued data as the send window allows, then a pending FIN.
    fn flush_stream(&mut self, id: StreamId) {
        let max_frame = self.config.max_frame_len as usize;
        loop {
            let Some(stream) = self.streams.get_mut(&id) else {
                return;
            };
            // Phase 1: data, in frames bounded by both the window and the frame size.
            let len = stream
                .pending
                .len()
                .min(stream.send_window as usize)
                .min(max_frame);
            if len > 0 {
                let chunk: Vec<u8> = stream.pending.drain(..len).collect();
                // Invariant: len <= send_window, so the subtraction cannot underflow.
                stream.send_window -= len as u32;
                // FIN rides on the last data frame when the owner already closed.
                let fin = matches!(stream.write, WriteState::Closing) && stream.pending.is_empty();
                let mut flags = mem::take(&mut stream.owed_flags);
                if fin {
                    flags = flags.union(Flags::FIN);
                    stream.write = WriteState::Closed;
                }
                self.write_frame(FrameType::Data, flags, id, len as u32, &chunk);
                continue;
            }
            // Phase 2: an empty FIN frame once nothing is held back.
            if matches!(stream.write, WriteState::Closing) && stream.pending.is_empty() {
                stream.write = WriteState::Closed;
                let flags = mem::take(&mut stream.owed_flags).union(Flags::FIN);
                self.write_frame(FrameType::Data, flags, id, 0, &[]);
            }
            break;
        }
        self.forget_if_done(id);
    }

    /// Drops a stream whose two directions are both finished.
    fn forget_if_done(&mut self, id: StreamId) {
        if self.streams.get(&id).is_some_and(Stream::is_done) {
            self.streams.remove(&id);
        }
    }

    /// Appends one frame to the outbound buffer.
    fn write_frame(
        &mut self,
        frame_type: FrameType,
        flags: Flags,
        id: StreamId,
        length: u32,
        body: &[u8],
    ) {
        let header = Header {
            frame_type,
            flags,
            stream_id: id,
            length,
        };
        self.outbound.extend_from_slice(&header.encode());
        self.outbound.extend_from_slice(body);
    }
}

#[cfg(test)]
mod tests {
    use std::iter::from_fn;

    use proptest::prelude::*;

    use super::*;

    /// Moves every pending byte from one session to the other, both ways, until quiet.
    fn pump(a: &mut Session, b: &mut Session) {
        loop {
            let to_b = a.take_output();
            let to_a = b.take_output();
            if to_a.is_empty() && to_b.is_empty() {
                return;
            }
            b.receive(&to_b).unwrap();
            a.receive(&to_a).unwrap();
        }
    }

    /// Drains every event of a session.
    fn events(session: &mut Session) -> Vec<SessionEvent> {
        from_fn(|| session.poll_event()).collect()
    }

    #[test]
    fn open_send_and_close() {
        let mut client = Session::new(Mode::Client, Config::default());
        let mut server = Session::new(Mode::Server, Config::default());

        // The client's first stream is 1, announced with a SYN window update.
        let id = client.open_stream().unwrap();
        assert_eq!(id, StreamId(1));
        assert_eq!(client.take_output(), [0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]);

        // Rewind: hand the SYN to the server, then send "hello" and close.
        server
            .receive(&[0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0])
            .unwrap();
        client.send(id, b"hello").unwrap();
        client.close(id).unwrap();
        pump(&mut client, &mut server);

        // The server sees the stream, the data, and the half-close in order.
        assert_eq!(
            events(&mut server),
            [
                SessionEvent::InboundStream(id),
                SessionEvent::Data {
                    stream: id,
                    data: b"hello".to_vec()
                },
                SessionEvent::StreamFinished(id),
            ]
        );

        // The server answers and closes: both directions are now done.
        server.send(id, b"hi").unwrap();
        server.close(id).unwrap();
        pump(&mut client, &mut server);
        assert_eq!(
            events(&mut client),
            [
                SessionEvent::Data {
                    stream: id,
                    data: b"hi".to_vec()
                },
                SessionEvent::StreamFinished(id)
            ]
        );
        assert_eq!(client.stream_count(), 0);
        assert_eq!(server.stream_count(), 0);
    }

    /// Total data bytes among events.
    fn data_len(events: &[SessionEvent]) -> usize {
        events
            .iter()
            .map(|event| match event {
                SessionEvent::Data { data, .. } => data.len(),
                _ => 0,
            })
            .sum()
    }

    #[test]
    fn credit_waits_for_the_owner_to_consume() {
        let mut client = Session::new(Mode::Client, Config::default());
        let mut server = Session::new(Mode::Server, Config::default());
        let id = client.open_stream().unwrap();

        // Fixture state: 256 KiB window, 300 KiB to send.
        //
        //     first flight: 256 KiB, window drops to 0
        //     44 KiB held back until the server grants credit
        let payload = vec![7u8; 300 * 1024];
        client.send(id, &payload).unwrap();
        let first = client.take_output();
        // 16 frames of 16 KiB each, plus the 12-byte SYN frame.
        assert_eq!(first.len(), 12 + 16 * (12 + 16 * 1024));

        // The server reads it all but consumes nothing: only its 12-byte ACK goes back.
        server.receive(&first).unwrap();
        pump(&mut client, &mut server);
        assert_eq!(data_len(&events(&mut server)), 256 * 1024);
        assert_eq!(
            client.writable(id),
            Config::default().max_send_buffer - 44 * 1024
        );

        // Consuming 100 KiB stays under the 128 KiB threshold: still no credit.
        server.consume(id, 100 * 1024);
        assert_eq!(server.take_output(), []);

        // 28 KiB more crosses it: one update grants all 128 KiB consumed.
        server.consume(id, 28 * 1024);
        let update = server.take_output();
        assert_eq!(update.len(), 12);
        assert_eq!(&update[8..12], &(128 * 1024u32).to_be_bytes());

        // The client sends the 44 KiB it held back.
        client.receive(&update).unwrap();
        pump(&mut client, &mut server);
        assert_eq!(data_len(&events(&mut server)), 44 * 1024);
    }

    #[test]
    fn consume_never_credits_more_than_received() {
        let mut client = Session::new(Mode::Client, Config::default());
        let mut server = Session::new(Mode::Server, Config::default());
        let id = client.open_stream().unwrap();
        client.send(id, &[1; 1000]).unwrap();
        pump(&mut client, &mut server);

        // Mutation: the owner claims 1 MiB consumed after receiving 1000 bytes.
        // The claim is capped at 1000, below the 128 KiB threshold, so nothing is granted.
        server.consume(id, 1024 * 1024);
        assert_eq!(server.take_output(), []);
    }

    #[test]
    fn send_buffer_is_bounded_per_stream() {
        let config = Config {
            max_send_buffer: 1000,
            ..Config::default()
        };
        let mut client = Session::new(Mode::Client, config);
        let id = client.open_stream().unwrap();

        // Fixture state: the peer never grants credit, so 256 KiB drain and the rest waits.
        // An idle stream takes 256 KiB + 600 bytes in one write; 600 stay held back.
        client.send(id, &vec![0; 256 * 1024 + 600]).unwrap();
        assert_eq!(client.writable(id), 400);

        // 400 more fit exactly; one byte beyond fails.
        client.send(id, &[0; 400]).unwrap();
        assert_eq!(client.writable(id), 0);
        assert_eq!(client.send(id, &[0]), Err(YamuxError::SendBufferFull(id)));
    }

    #[test]
    fn data_beyond_the_window_is_a_protocol_error() {
        let mut server = Session::new(Mode::Server, Config::default());
        // Mutation: a SYN data frame claiming 256 KiB + 1 bytes.
        let header = Header {
            frame_type: FrameType::Data,
            flags: Flags::SYN,
            stream_id: StreamId(1),
            length: INITIAL_WINDOW + 1,
        };
        assert_eq!(
            server.receive(&header.encode()),
            Err(YamuxError::WindowExceeded {
                stream: StreamId(1),
                len: INITIAL_WINDOW + 1,
                window: INITIAL_WINDOW
            })
        );
        // The session answers with go-away code 1.
        assert_eq!(server.take_output(), [0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn wrong_parity_and_duplicate_syn() {
        // A client peer may not open even stream 2 on a server.
        let mut server = Session::new(Mode::Server, Config::default());
        let syn = |id| {
            Header {
                frame_type: FrameType::WindowUpdate,
                flags: Flags::SYN,
                stream_id: StreamId(id),
                length: 0,
            }
            .encode()
        };
        assert_eq!(
            server.receive(&syn(2)),
            Err(YamuxError::InvalidStreamId(StreamId(2)))
        );
        // Opening stream 1 twice is a duplicate.
        let mut server = Session::new(Mode::Server, Config::default());
        server.receive(&syn(1)).unwrap();
        assert_eq!(
            server.receive(&syn(1)),
            Err(YamuxError::DuplicateStream(StreamId(1)))
        );
    }

    #[test]
    fn ping_is_echoed() {
        let mut client = Session::new(Mode::Client, Config::default());
        let mut server = Session::new(Mode::Server, Config::default());
        client.ping(42);
        pump(&mut client, &mut server);
        assert_eq!(events(&mut client), [SessionEvent::Pong(42)]);
        assert_eq!(events(&mut server), []);
    }

    #[test]
    fn go_away_stops_new_streams() {
        let mut client = Session::new(Mode::Client, Config::default());
        let mut server = Session::new(Mode::Server, Config::default());
        server.go_away(GoAwayCode::Normal);
        pump(&mut client, &mut server);
        assert_eq!(
            events(&mut client),
            [SessionEvent::GoAway(GoAwayCode::Normal)]
        );
        assert_eq!(client.open_stream(), Err(YamuxError::SessionClosing));
    }

    #[test]
    fn reset_reaches_the_peer() {
        let mut client = Session::new(Mode::Client, Config::default());
        let mut server = Session::new(Mode::Server, Config::default());
        let id = client.open_stream().unwrap();
        pump(&mut client, &mut server);
        client.reset(id).unwrap();
        pump(&mut client, &mut server);
        assert_eq!(
            events(&mut server),
            [
                SessionEvent::InboundStream(id),
                SessionEvent::StreamReset(id)
            ]
        );
        assert!(!server.is_open(id));
    }

    #[test]
    fn ack_backlog_is_bounded() {
        let config = Config {
            max_ack_backlog: 2,
            ..Config::default()
        };
        let mut client = Session::new(Mode::Client, config);
        // Two unacknowledged streams fill a backlog of 2.
        client.open_stream().unwrap();
        client.open_stream().unwrap();
        assert_eq!(client.open_stream(), Err(YamuxError::AckBacklogFull));
    }

    #[test]
    fn larger_window_is_announced_on_open() {
        // A 1 MiB window announces 1 MiB - 256 KiB = 786432 extra on the SYN.
        let config = Config {
            receive_window: 1024 * 1024,
            ..Config::default()
        };
        let mut client = Session::new(Mode::Client, config);
        client.open_stream().unwrap();
        let frame = client.take_output();
        assert_eq!(&frame[8..12], &786_432u32.to_be_bytes());
    }

    proptest! {
        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = Session::new(Mode::Server, Config::default()).receive(&bytes);
            let _ = Session::new(Mode::Client, Config::default()).receive(&bytes);
        }

        #[test]
        fn data_arrives_intact_under_any_split(
            payload in proptest::collection::vec(any::<u8>(), 0..70_000),
            cut in 1usize..4096,
        ) {
            // Deliver the client's bytes to the server in chunks of a random size.
            let mut client = Session::new(Mode::Client, Config::default());
            let mut server = Session::new(Mode::Server, Config::default());
            let id = client.open_stream().unwrap();
            client.send(id, &payload).unwrap();
            client.close(id).unwrap();
            for chunk in client.take_output().chunks(cut) {
                server.receive(chunk).unwrap();
            }
            let mut received = Vec::new();
            let mut finished = false;
            while let Some(event) = server.poll_event() {
                match event {
                    SessionEvent::Data { data, .. } => received.extend(data),
                    SessionEvent::StreamFinished(_) => finished = true,
                    _ => {}
                }
            }
            prop_assert_eq!(received, payload);
            prop_assert!(finished);
        }
    }
}
