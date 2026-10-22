//! Every stream of a connection, with stream limits and connection-wide flow control.
//!
//! # Overview
//!
//! Only bidirectional streams exist here: libp2p opens no other kind.
//! A peer's unidirectional stream is refused with STREAM_LIMIT_ERROR, as its limit is zero.
//!
//! Limits come in three layers, per RFC 9000, section 4:
//!
//! - each stream's receive credit, raised as the owner consumes
//! - the connection's receive credit, over all streams together
//! - the count of streams the peer may open, raised as its streams end
//!
//! A stream leaves the map once both halves are done.
//! Its id is never reused, so late frames for it are ignored.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::{
    RecvBuffer, SendBuffer, Side, StreamId,
    credit::{RecvCredit, SendCredit},
    send::Chunk,
};
use crate::quic::{
    Event, QuicError, TransportError, TransportErrorCode, VarInt, frame::Frame,
    transport_parameters::TransportParameters,
};

/// The application error code a local abort sends.
///
/// libp2p defines no codes for stream resets, so zero stands for a plain abort.
const RESET_CODE: u64 = 0;

/// Local limits for the streams of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamLimits {
    /// Receive credit of each stream.
    pub stream_window: u64,
    /// Receive credit of the whole connection.
    pub connection_window: u64,
    /// Streams the peer may have open at once.
    pub max_inbound_streams: u64,
    /// Unsent bytes a stream holds before writes are refused.
    pub send_buffer: usize,
}

/// A frame the streams sent, kept until it is acknowledged or lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamRecord {
    /// Stream data, possibly with the FIN.
    Data {
        /// The stream.
        id: StreamId,
        /// The bytes sent.
        chunk: Chunk,
    },
    /// A RESET_STREAM.
    Reset {
        /// The stream.
        id: StreamId,
    },
    /// A STOP_SENDING.
    StopSending {
        /// The stream.
        id: StreamId,
    },
    /// A MAX_STREAM_DATA.
    MaxStreamData {
        /// The stream.
        id: StreamId,
        /// The limit sent.
        limit: u64,
    },
    /// A MAX_DATA.
    MaxData {
        /// The limit sent.
        limit: u64,
    },
    /// A MAX_STREAMS for bidirectional streams.
    MaxStreams {
        /// The count sent.
        limit: u64,
    },
    /// A blocked frame, which is informational and not repeated.
    Blocked,
}

/// The state of a stream's sending half.
#[derive(Clone, Debug)]
enum SendHalf {
    /// The owner may write.
    Open(SendBuffer),
    /// This side abandoned the stream.
    Reset {
        /// The final size sent.
        final_size: u64,
        /// Whether a RESET_STREAM must go out.
        due: bool,
        /// Whether the peer acknowledged it.
        acked: bool,
    },
}

/// The state of a stream's receiving half.
#[derive(Clone, Debug)]
enum RecvHalf {
    /// Data may still arrive.
    Open(RecvBuffer),
    /// The stream finished, or the peer reset it; nothing more is reported.
    Done,
    /// This side asked the peer to stop.
    Stopped {
        /// Whether a STOP_SENDING must go out.
        due: bool,
    },
}

/// One stream.
#[derive(Clone, Debug)]
struct Stream {
    /// The sending half.
    send: SendHalf,
    /// The peer's limit on this stream.
    send_credit: SendCredit,
    /// The receiving half.
    recv: RecvHalf,
    /// This side's limit on this stream.
    recv_credit: RecvCredit,
    /// Whether the owner still sees this stream; a local abort hides it at once.
    visible: bool,
}

impl Stream {
    /// Whether both halves are done and the map may forget the stream.
    fn is_done(&self) -> bool {
        let send_done = match &self.send {
            SendHalf::Open(buffer) => buffer.is_complete(),
            SendHalf::Reset { acked, .. } => *acked,
        };
        let recv_done = match self.recv {
            RecvHalf::Open(_) => false,
            RecvHalf::Done => true,
            RecvHalf::Stopped { due } => !due,
        };
        send_done && recv_done
    }
}

/// The streams of one connection.
#[derive(Debug)]
pub(crate) struct Streams {
    /// This endpoint's side.
    side: Side,
    /// Local limits.
    limits: StreamLimits,
    /// Live streams.
    streams: BTreeMap<StreamId, Stream>,
    /// Streams that may have frames to send.
    ready: BTreeSet<StreamId>,
    /// Index of the next stream this side opens.
    next_local: u64,
    /// Streams this side may open in all, as the peer allows.
    local_limit: u64,
    /// Whether a STREAMS_BLOCKED report is due.
    streams_blocked_due: bool,
    /// Index of the next stream the peer may open.
    next_remote: u64,
    /// Peer streams that ended, which raise the peer's stream allowance.
    remote_closed: u64,
    /// The stream count the peer may open, as advertised.
    remote_limit: u64,
    /// Whether a MAX_STREAMS must go out.
    remote_limit_due: bool,
    /// The peer's initial credit for streams this side opens.
    peer_window_local: u64,
    /// The peer's initial credit for streams the peer opens.
    peer_window_remote: u64,
    /// The peer's connection-wide limit.
    connection_send: SendCredit,
    /// New bytes sent over all streams.
    connection_sent: u64,
    /// This side's connection-wide limit.
    connection_recv: RecvCredit,
    /// Bytes received over all streams, counting each stream's highest offset.
    connection_received: u64,
    /// Events for the owner.
    pub(crate) events: VecDeque<Event>,
    /// The stream where the next round of data starts, for fairness.
    cursor: Option<StreamId>,
}

impl Streams {
    /// No streams, with limits that wait for the peer's transport parameters.
    pub(crate) fn new(side: Side, limits: StreamLimits) -> Self {
        Self {
            side,
            limits,
            streams: BTreeMap::new(),
            ready: BTreeSet::new(),
            next_local: 0,
            local_limit: 0,
            streams_blocked_due: false,
            next_remote: 0,
            remote_closed: 0,
            remote_limit: limits.max_inbound_streams,
            remote_limit_due: false,
            peer_window_local: 0,
            peer_window_remote: 0,
            connection_send: SendCredit::new(0),
            connection_sent: 0,
            connection_recv: RecvCredit::new(limits.connection_window),
            connection_received: 0,
            events: VecDeque::new(),
            cursor: None,
        }
    }

    /// Writes this side's limits into its transport parameters.
    pub(crate) const fn write_parameters(&self, params: &mut TransportParameters) {
        params.initial_max_data = self.limits.connection_window;
        params.initial_max_stream_data_bidi_local = self.limits.stream_window;
        params.initial_max_stream_data_bidi_remote = self.limits.stream_window;
        params.initial_max_stream_data_uni = 0;
        params.initial_max_streams_bidi = self.limits.max_inbound_streams;
        params.initial_max_streams_uni = 0;
    }

    /// Applies the peer's limits from its transport parameters.
    pub(crate) fn apply_peer_parameters(&mut self, params: &TransportParameters) {
        self.local_limit = params.initial_max_streams_bidi;
        // Streams this side opens are remote to the peer; streams the peer opens are local to it.
        self.peer_window_local = params.initial_max_stream_data_bidi_remote;
        self.peer_window_remote = params.initial_max_stream_data_bidi_local;
        self.connection_send.raise(params.initial_max_data);
    }

    /// Opens a stream.
    pub(crate) fn open(&mut self) -> Result<StreamId, QuicError> {
        if self.next_local >= self.local_limit {
            self.streams_blocked_due = true;
            return Err(QuicError::StreamLimit {
                max: self.local_limit,
            });
        }
        let id = StreamId::bidi(self.side, self.next_local);
        self.next_local += 1;
        self.insert(id, self.peer_window_local);
        Ok(id)
    }

    /// Adds a stream with a send credit.
    fn insert(&mut self, id: StreamId, send_window: u64) {
        self.streams.insert(
            id,
            Stream {
                send: SendHalf::Open(SendBuffer::default()),
                send_credit: SendCredit::new(send_window),
                recv: RecvHalf::Open(RecvBuffer::default()),
                recv_credit: RecvCredit::new(self.limits.stream_window),
                visible: true,
            },
        );
    }

    /// The stream as the owner sees it.
    fn visible(&mut self, id: StreamId) -> Result<&mut Stream, QuicError> {
        self.streams
            .get_mut(&id)
            .filter(|stream| stream.visible)
            .ok_or(QuicError::UnknownStream(id))
    }

    /// Queues data on a stream.
    ///
    /// An idle stream takes any write; a backed-up one only up to the send buffer.
    pub(crate) fn send(&mut self, id: StreamId, data: &[u8]) -> Result<(), QuicError> {
        let cap = self.limits.send_buffer;
        let stream = self.visible(id)?;
        let SendHalf::Open(buffer) = &mut stream.send else {
            return Err(QuicError::StreamClosed(id));
        };
        if buffer.is_finished() {
            return Err(QuicError::StreamClosed(id));
        }
        let pending = buffer.unsent_len() as usize;
        if pending > 0 && pending + data.len() > cap {
            return Err(QuicError::SendBufferFull {
                stream: id,
                len: data.len(),
                pending,
                max: cap,
            });
        }
        buffer.write(data);
        self.ready.insert(id);
        Ok(())
    }

    /// Bytes a stream accepts before its send buffer is full, or zero when it cannot be written.
    pub(crate) fn writable(&self, id: StreamId) -> usize {
        match self.streams.get(&id) {
            Some(Stream {
                send: SendHalf::Open(buffer),
                visible: true,
                ..
            }) if !buffer.is_finished() => self
                .limits
                .send_buffer
                .saturating_sub(buffer.unsent_len() as usize),
            _ => 0,
        }
    }

    /// Whether the owner sees the stream as open.
    pub(crate) fn is_open(&self, id: StreamId) -> bool {
        self.streams.get(&id).is_some_and(|stream| stream.visible)
    }

    /// Credits consumed bytes to the stream and the connection.
    pub(crate) fn consume(&mut self, id: StreamId, len: usize) {
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.recv_credit.consume(len as u64);
            if stream.recv_credit.is_update_due() {
                self.ready.insert(id);
            }
        }
        self.connection_recv.consume(len as u64);
    }

    /// Finishes the stream once its queued data is sent.
    pub(crate) fn close(&mut self, id: StreamId) -> Result<(), QuicError> {
        let stream = self.visible(id)?;
        if let SendHalf::Open(buffer) = &mut stream.send {
            buffer.finish();
        }
        self.ready.insert(id);
        Ok(())
    }

    /// Aborts both halves of a stream; the owner sees it no more.
    pub(crate) fn reset(&mut self, id: StreamId) -> Result<(), QuicError> {
        let stream = self.visible(id)?;
        stream.visible = false;
        if let SendHalf::Open(buffer) = &stream.send
            && !buffer.is_complete()
        {
            stream.send = SendHalf::Reset {
                final_size: buffer.sent_end(),
                due: true,
                acked: false,
            };
        }
        if matches!(stream.recv, RecvHalf::Open(_)) {
            stream.recv = RecvHalf::Stopped { due: true };
        }
        self.ready.insert(id);
        self.forget_if_done(id);
        Ok(())
    }

    /// Finds the stream a peer frame names, opening peer streams it implies.
    ///
    /// # Returns
    ///
    /// The stream, or nothing when it already ended and the frame is stale.
    ///
    /// # Errors
    ///
    /// Fails on a unidirectional stream, one beyond the peer's limit, or a local one never opened.
    fn peer_stream(
        &mut self,
        id: StreamId,
        frame_type: u64,
    ) -> Result<Option<&mut Stream>, TransportError> {
        if id.is_unidirectional() {
            return Err(TransportError::new(
                TransportErrorCode::STREAM_LIMIT_ERROR,
                format!("unidirectional stream {id} exceeds the limit of zero"),
            )
            .on_frame(frame_type));
        }
        if id.initiator() == self.side {
            if id.index() >= self.next_local {
                return Err(TransportError::new(
                    TransportErrorCode::STREAM_STATE_ERROR,
                    format!("frame for local stream {id} never opened"),
                )
                .on_frame(frame_type));
            }
            return Ok(self.streams.get_mut(&id));
        }
        if id.index() >= self.remote_limit {
            return Err(TransportError::new(
                TransportErrorCode::STREAM_LIMIT_ERROR,
                format!("peer stream {id} beyond the limit of {}", self.remote_limit),
            )
            .on_frame(frame_type));
        }
        // Opening a stream opens every lower one of its type, per RFC 9000, section 3.2.
        while self.next_remote <= id.index() {
            let opened = StreamId::bidi(self.side.peer(), self.next_remote);
            self.next_remote += 1;
            self.insert(opened, self.peer_window_remote);
            self.events.push_back(Event::InboundStream(opened));
        }
        Ok(self.streams.get_mut(&id))
    }

    /// Handles a stream-related frame from the peer.
    pub(crate) fn on_frame(&mut self, frame: &Frame<'_>) -> Result<(), TransportError> {
        let frame_type = frame.frame_type();
        match *frame {
            Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => self.on_stream_data(id, offset, data, fin, frame_type),
            Frame::ResetStream { id, final_size, .. } => self.on_reset(id, final_size, frame_type),
            Frame::StopSending { id, .. } => {
                if let Some(stream) = self.peer_stream(id, frame_type)? {
                    // The peer wants no more data: abandon the sending half, per RFC 9000, section 3.5.
                    if let SendHalf::Open(buffer) = &stream.send
                        && !buffer.is_complete()
                    {
                        stream.send = SendHalf::Reset {
                            final_size: buffer.sent_end(),
                            due: true,
                            acked: false,
                        };
                        if stream.visible {
                            stream.visible = false;
                            self.events.push_back(Event::StreamReset(id));
                        }
                    }
                    self.ready.insert(id);
                }
                Ok(())
            }
            Frame::MaxStreamData { id, max } => {
                if let Some(stream) = self.peer_stream(id, frame_type)? {
                    stream.send_credit.raise(max);
                    self.ready.insert(id);
                }
                Ok(())
            }
            Frame::MaxData(max) => {
                self.connection_send.raise(max);
                self.ready.extend(self.streams.keys().copied());
                Ok(())
            }
            Frame::MaxStreams { bidi: true, max } => {
                self.local_limit = self.local_limit.max(max);
                Ok(())
            }
            // Unidirectional limits and blocked reports need no action.
            _ => Ok(()),
        }
    }

    /// Takes in stream data.
    fn on_stream_data(
        &mut self,
        id: StreamId,
        offset: u64,
        data: &[u8],
        fin: bool,
        frame_type: u64,
    ) -> Result<(), TransportError> {
        let Some(stream) = self.peer_stream(id, frame_type)? else {
            return Ok(());
        };
        let RecvHalf::Open(buffer) = &mut stream.recv else {
            return Ok(());
        };
        let before = buffer.highest();
        buffer
            .insert(offset, data, fin)
            .map_err(|error| error.on_frame(frame_type))?;
        let highest = buffer.highest();
        if !stream.recv_credit.allows(highest) {
            return Err(TransportError::new(
                TransportErrorCode::FLOW_CONTROL_ERROR,
                format!(
                    "stream {id} data reaches {highest}, beyond the limit of {}",
                    stream.recv_credit.limit()
                ),
            )
            .on_frame(frame_type));
        }
        self.connection_received += highest - before;
        if !self.connection_recv.allows(self.connection_received) {
            return Err(TransportError::new(
                TransportErrorCode::FLOW_CONTROL_ERROR,
                format!(
                    "connection data reaches {}, beyond the limit of {}",
                    self.connection_received,
                    self.connection_recv.limit()
                ),
            )
            .on_frame(frame_type));
        }
        self.deliver(id);
        Ok(())
    }

    /// Reports the bytes of a stream that became contiguous, and its end.
    fn deliver(&mut self, id: StreamId) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        let RecvHalf::Open(buffer) = &mut stream.recv else {
            return;
        };
        let ready = buffer.take_ready();
        let finished = buffer.is_finished();
        if stream.visible {
            if let Some(data) = ready {
                self.events.push_back(Event::Data { stream: id, data });
            }
            if finished {
                self.events.push_back(Event::StreamFinished(id));
            }
        }
        if finished {
            stream.recv = RecvHalf::Done;
            self.forget_if_done(id);
        }
    }

    /// Takes in a RESET_STREAM.
    fn on_reset(
        &mut self,
        id: StreamId,
        final_size: u64,
        frame_type: u64,
    ) -> Result<(), TransportError> {
        let Some(stream) = self.peer_stream(id, frame_type)? else {
            return Ok(());
        };
        let RecvHalf::Open(buffer) = &mut stream.recv else {
            return Ok(());
        };
        let before = buffer.highest();
        buffer
            .reset(final_size)
            .map_err(|error| error.on_frame(frame_type))?;
        if !stream.recv_credit.allows(final_size) {
            return Err(TransportError::new(
                TransportErrorCode::FLOW_CONTROL_ERROR,
                format!("stream {id} final size {final_size} beyond its limit"),
            )
            .on_frame(frame_type));
        }
        // The unread rest of a reset stream counts as received and consumed at once.
        let unread = final_size - buffer.delivered();
        stream.recv = RecvHalf::Done;
        let was_visible = stream.visible;
        stream.visible = false;
        // A reset stream sends no more either: abandon the sending half too.
        if let SendHalf::Open(buffer) = &stream.send
            && !buffer.is_complete()
        {
            stream.send = SendHalf::Reset {
                final_size: buffer.sent_end(),
                due: true,
                acked: false,
            };
            self.ready.insert(id);
        }
        if was_visible {
            self.events.push_back(Event::StreamReset(id));
        }
        self.connection_received += final_size - before;
        self.connection_recv.consume(unread);
        self.forget_if_done(id);
        Ok(())
    }

    /// Drops a finished stream, raising the peer's allowance when it was a peer stream.
    fn forget_if_done(&mut self, id: StreamId) {
        if !self.streams.get(&id).is_some_and(Stream::is_done) {
            return;
        }
        self.streams.remove(&id);
        self.ready.remove(&id);
        if id.initiator() != self.side {
            self.remote_closed += 1;
            self.remote_limit = self.remote_closed + self.limits.max_inbound_streams;
            self.remote_limit_due = true;
        }
    }

    /// Whether any stream frame waits to be sent.
    pub(crate) fn has_pending(&self) -> bool {
        !self.ready.is_empty()
            || self.remote_limit_due
            || self.streams_blocked_due
            || self.connection_recv.is_update_due()
    }

    /// Writes control frames, then data, into a payload up to a size.
    ///
    /// Streams take turns, starting after the one that went last, so one busy stream cannot starve the rest.
    pub(crate) fn write(&mut self, out: &mut Vec<u8>, max: usize, records: &mut Vec<StreamRecord>) {
        self.write_connection_control(out, max, records);
        let order: Vec<StreamId> = match self.cursor {
            Some(cursor) => self
                .ready
                .range(cursor..)
                .skip(1)
                .chain(self.ready.range(..=cursor))
                .copied()
                .collect(),
            None => self.ready.iter().copied().collect(),
        };
        for id in order {
            if out.len() + 3 >= max {
                break;
            }
            self.write_stream(id, out, max, records);
            self.cursor = Some(id);
        }
    }

    /// Writes connection-wide control frames.
    fn write_connection_control(
        &mut self,
        out: &mut Vec<u8>,
        max: usize,
        records: &mut Vec<StreamRecord>,
    ) {
        // Each control frame is at most 9 bytes: a type byte and an eight-byte varint.
        if out.len() + 9 <= max
            && let Some(limit) = self.connection_recv.take_update()
        {
            Frame::MaxData(limit).encode(out);
            records.push(StreamRecord::MaxData { limit });
        }
        if out.len() + 9 <= max && self.remote_limit_due {
            self.remote_limit_due = false;
            Frame::MaxStreams {
                bidi: true,
                max: self.remote_limit,
            }
            .encode(out);
            records.push(StreamRecord::MaxStreams {
                limit: self.remote_limit,
            });
        }
        if out.len() + 9 <= max && self.streams_blocked_due {
            self.streams_blocked_due = false;
            Frame::StreamsBlocked {
                bidi: true,
                limit: self.local_limit,
            }
            .encode(out);
            records.push(StreamRecord::Blocked);
        }
        if out.len() + 9 <= max
            && let Some(limit) = self.connection_send.take_blocked()
        {
            Frame::DataBlocked(limit).encode(out);
            records.push(StreamRecord::Blocked);
        }
    }

    /// Writes one stream's due frames.
    fn write_stream(
        &mut self,
        id: StreamId,
        out: &mut Vec<u8>,
        max: usize,
        records: &mut Vec<StreamRecord>,
    ) {
        let connection_room = self
            .connection_send
            .limit()
            .saturating_sub(self.connection_sent);
        let Some(stream) = self.streams.get_mut(&id) else {
            self.ready.remove(&id);
            return;
        };
        // Control frames of the stream: at most 1 + 8 + 8 + 8 bytes each.
        if out.len() + 25 <= max
            && let SendHalf::Reset {
                final_size, due, ..
            } = &mut stream.send
            && *due
        {
            *due = false;
            Frame::ResetStream {
                id,
                error_code: RESET_CODE,
                final_size: *final_size,
            }
            .encode(out);
            records.push(StreamRecord::Reset { id });
        }
        if out.len() + 25 <= max
            && let RecvHalf::Stopped { due } = &mut stream.recv
            && *due
        {
            *due = false;
            Frame::StopSending {
                id,
                error_code: RESET_CODE,
            }
            .encode(out);
            records.push(StreamRecord::StopSending { id });
        }
        if out.len() + 25 <= max
            && matches!(stream.recv, RecvHalf::Open(_))
            && let Some(limit) = stream.recv_credit.take_update()
        {
            Frame::MaxStreamData { id, max: limit }.encode(out);
            records.push(StreamRecord::MaxStreamData { id, limit });
        }
        // Data, as far as the frame, the stream credit and the connection credit allow.
        if let SendHalf::Open(buffer) = &mut stream.send {
            let limit = stream.send_credit.limit();
            let before = buffer.sent_end();
            // New bytes may not exceed the connection room either.
            let new_limit = limit.min(before + connection_room);
            // Room for the worst-case header: an eight-byte offset and a length up to the frame size.
            let header = Frame::stream_header_len(id, VarInt::MAX.get(), max);
            if out.len() + header < max
                && let Some(chunk) = buffer.next_chunk(max - out.len() - header, new_limit)
            {
                let end = chunk.offset + chunk.len as u64;
                self.connection_sent += end.saturating_sub(before);
                Self::encode_stream_frame(id, chunk, buffer, out);
                records.push(StreamRecord::Data { id, chunk });
            }
            if buffer.unsent_len() > 0 && buffer.sent_end() >= limit {
                stream.send_credit.on_blocked();
            }
            if buffer.unsent_len() > 0 && self.connection_sent >= self.connection_send.limit() {
                self.connection_send.on_blocked();
            }
        }
        // A stream with nothing left to send leaves the ready set until something changes.
        if !Self::stream_pending(stream, connection_room) {
            self.ready.remove(&id);
        }
    }

    /// Writes a STREAM frame for a chunk of a buffer.
    fn encode_stream_frame(id: StreamId, chunk: Chunk, buffer: &SendBuffer, out: &mut Vec<u8>) {
        let mut data = Vec::with_capacity(chunk.len);
        buffer.copy(chunk, &mut data);
        Frame::Stream {
            id,
            offset: chunk.offset,
            data: &data,
            fin: chunk.fin,
        }
        .encode(out);
    }

    /// Whether a stream still has frames to send.
    fn stream_pending(stream: &Stream, connection_room: u64) -> bool {
        let send = match &stream.send {
            SendHalf::Open(buffer) => {
                let limit = stream
                    .send_credit
                    .limit()
                    .min(buffer.sent_end() + connection_room);
                buffer.has_pending(limit)
            }
            SendHalf::Reset { due, .. } => *due,
        };
        let recv = matches!(stream.recv, RecvHalf::Stopped { due: true })
            || (matches!(stream.recv, RecvHalf::Open(_)) && stream.recv_credit.is_update_due());
        send || recv
    }

    /// Records that a sent frame was acknowledged.
    pub(crate) fn on_acked(&mut self, record: StreamRecord) {
        match record {
            StreamRecord::Data { id, chunk } => {
                if let Some(Stream {
                    send: SendHalf::Open(buffer),
                    ..
                }) = self.streams.get_mut(&id)
                {
                    buffer.on_acked(chunk);
                }
                self.forget_if_done(id);
            }
            StreamRecord::Reset { id } => {
                if let Some(Stream {
                    send: SendHalf::Reset { acked, .. },
                    ..
                }) = self.streams.get_mut(&id)
                {
                    *acked = true;
                }
                self.forget_if_done(id);
            }
            StreamRecord::StopSending { .. }
            | StreamRecord::MaxStreamData { .. }
            | StreamRecord::MaxData { .. }
            | StreamRecord::MaxStreams { .. }
            | StreamRecord::Blocked => {}
        }
    }

    /// Records that a sent frame was lost, scheduling what must go out again.
    pub(crate) fn on_lost(&mut self, record: StreamRecord) {
        match record {
            StreamRecord::Data { id, chunk } => {
                if let Some(Stream {
                    send: SendHalf::Open(buffer),
                    ..
                }) = self.streams.get_mut(&id)
                {
                    buffer.on_lost(chunk);
                    self.ready.insert(id);
                }
            }
            StreamRecord::Reset { id } => {
                if let Some(Stream {
                    send: SendHalf::Reset { due, acked, .. },
                    ..
                }) = self.streams.get_mut(&id)
                    && !*acked
                {
                    *due = true;
                    self.ready.insert(id);
                }
            }
            StreamRecord::StopSending { id } => {
                if let Some(Stream {
                    recv: RecvHalf::Stopped { due },
                    ..
                }) = self.streams.get_mut(&id)
                {
                    *due = true;
                    self.ready.insert(id);
                }
            }
            StreamRecord::MaxStreamData { id, limit } => {
                if let Some(stream) = self.streams.get_mut(&id) {
                    stream.recv_credit.on_update_lost(limit);
                    self.ready.insert(id);
                }
            }
            StreamRecord::MaxData { limit } => self.connection_recv.on_update_lost(limit),
            StreamRecord::MaxStreams { limit } => {
                if limit == self.remote_limit {
                    self.remote_limit_due = true;
                }
            }
            StreamRecord::Blocked => {}
        }
    }

    /// Live streams, including those the owner aborted but the peer has not yet acknowledged.
    pub(crate) fn len(&self) -> usize {
        self.streams.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::frame::FrameIter;

    const LIMITS: StreamLimits = StreamLimits {
        stream_window: 1000,
        connection_window: 1500,
        max_inbound_streams: 2,
        send_buffer: 4096,
    };

    /// A client and a server that exchanged transport parameters.
    fn pair() -> (Streams, Streams) {
        let mut client = Streams::new(Side::Client, LIMITS);
        let mut server = Streams::new(Side::Server, LIMITS);
        let mut params = TransportParameters::default();
        server.write_parameters(&mut params);
        client.apply_peer_parameters(&params);
        client.write_parameters(&mut params);
        server.apply_peer_parameters(&params);
        (client, server)
    }

    /// Sends one payload of up to 1200 bytes from one side to the other, acknowledging it.
    fn pump(from: &mut Streams, to: &mut Streams) -> Result<usize, TransportError> {
        let mut out = Vec::new();
        let mut records = Vec::new();
        from.write(&mut out, 1200, &mut records);
        for frame in FrameIter::new(&out) {
            to.on_frame(&frame.unwrap())?;
        }
        for record in records {
            from.on_acked(record);
        }
        Ok(out.len())
    }

    fn events(streams: &mut Streams) -> Vec<Event> {
        streams.events.drain(..).collect()
    }

    fn data_len(events: &[Event]) -> usize {
        events
            .iter()
            .map(|event| match event {
                Event::Data { data, .. } => data.len(),
                _ => 0,
            })
            .sum()
    }

    #[test]
    fn a_stream_carries_data_and_its_end() {
        let (mut client, mut server) = pair();
        let id = client.open().unwrap();
        assert_eq!(id, StreamId(0));
        client.send(id, b"hello").unwrap();
        client.close(id).unwrap();
        pump(&mut client, &mut server).unwrap();
        assert_eq!(
            events(&mut server),
            [
                Event::InboundStream(id),
                Event::Data {
                    stream: id,
                    data: b"hello".to_vec()
                },
                Event::StreamFinished(id),
            ]
        );

        // The server answers and finishes; both halves end and the stream is forgotten.
        server.send(id, b"hi").unwrap();
        server.close(id).unwrap();
        pump(&mut server, &mut client).unwrap();
        assert_eq!(
            events(&mut client),
            [
                Event::Data {
                    stream: id,
                    data: b"hi".to_vec()
                },
                Event::StreamFinished(id)
            ]
        );
        assert_eq!((client.len(), server.len()), (0, 0));
    }

    #[test]
    fn stream_limits_and_their_renewal() {
        let (mut client, mut server) = pair();
        // The server allows two streams; the third is refused.
        let first = client.open().unwrap();
        client.open().unwrap();
        assert_eq!(client.open(), Err(QuicError::StreamLimit { max: 2 }));

        // A frame for stream 8, the client's third, breaks the server's limit.
        let frame = Frame::Stream {
            id: StreamId(8),
            offset: 0,
            data: b"x",
            fin: false,
        };
        assert_eq!(
            server.on_frame(&frame).map_err(|error| error.code),
            Err(TransportErrorCode::STREAM_LIMIT_ERROR)
        );

        // Once the first stream ends both ways, the server grants a third.
        client.close(first).unwrap();
        pump(&mut client, &mut server).unwrap();
        server.close(first).unwrap();
        pump(&mut server, &mut client).unwrap();
        // The acknowledgment of the server's FIN ends the stream; MAX_STREAMS follows.
        assert_eq!(client.open(), Err(QuicError::StreamLimit { max: 2 }));
        pump(&mut server, &mut client).unwrap();
        assert_eq!(client.open(), Ok(StreamId(8)));
    }

    #[test]
    fn flow_control_stalls_until_consumed() {
        let (mut client, mut server) = pair();
        let id = client.open().unwrap();
        client.send(id, &[1; 2000]).unwrap();

        // The stream window of 1000 stops the client mid-way.
        pump(&mut client, &mut server).unwrap();
        pump(&mut client, &mut server).unwrap();
        assert_eq!(data_len(&events(&mut server)), 1000);

        // Consuming 600 raises the stream limit to 1600; the connection limit of 1500 binds first.
        server.consume(id, 600);
        pump(&mut server, &mut client).unwrap();
        pump(&mut client, &mut server).unwrap();
        assert_eq!(data_len(&events(&mut server)), 500);
    }

    #[test]
    fn data_beyond_the_limit_is_a_flow_control_error() {
        let (_, mut server) = pair();
        let frame = Frame::Stream {
            id: StreamId(0),
            offset: 1000,
            data: b"x",
            fin: false,
        };
        assert_eq!(
            server.on_frame(&frame).map_err(|error| error.code),
            Err(TransportErrorCode::FLOW_CONTROL_ERROR)
        );
    }

    #[test]
    fn a_local_reset_aborts_both_halves() {
        let (mut client, mut server) = pair();
        let id = client.open().unwrap();
        client.send(id, b"partial").unwrap();
        pump(&mut client, &mut server).unwrap();
        events(&mut server);

        // The client aborts: RESET_STREAM and STOP_SENDING reach the server.
        client.reset(id).unwrap();
        assert!(!client.is_open(id));
        assert_eq!(client.send(id, b"more"), Err(QuicError::UnknownStream(id)));
        pump(&mut client, &mut server).unwrap();
        assert_eq!(events(&mut server), [Event::StreamReset(id)]);

        // The server's own reset completes the exchange, and both forget the stream.
        pump(&mut server, &mut client).unwrap();
        assert_eq!((client.len(), server.len()), (0, 0));
        assert!(events(&mut client).is_empty());
    }

    #[test]
    fn unidirectional_and_unopened_streams_are_refused() {
        let (_, mut server) = pair();
        // Stream 2 is client-initiated and unidirectional.
        let frame = Frame::Stream {
            id: StreamId(2),
            offset: 0,
            data: b"",
            fin: false,
        };
        assert_eq!(
            server.on_frame(&frame).map_err(|error| error.code),
            Err(TransportErrorCode::STREAM_LIMIT_ERROR)
        );
        // Stream 1 is the server's own, which it never opened.
        let frame = Frame::MaxStreamData {
            id: StreamId(1),
            max: 10,
        };
        assert_eq!(
            server.on_frame(&frame).map_err(|error| error.code),
            Err(TransportErrorCode::STREAM_STATE_ERROR)
        );
    }

    #[test]
    fn a_full_send_buffer_refuses_writes() {
        let (mut client, _) = pair();
        let id = client.open().unwrap();
        // An idle stream takes 5000 bytes past the 4096 cap; then it is backed up.
        client.send(id, &[0; 5000]).unwrap();
        assert_eq!(client.writable(id), 0);
        assert_eq!(
            client.send(id, b"x"),
            Err(QuicError::SendBufferFull {
                stream: id,
                len: 1,
                pending: 5000,
                max: 4096
            })
        );
    }
}
