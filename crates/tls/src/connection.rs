//! A TLS endpoint over a byte stream: the handshake, the record layer, and application data.
//!
//! # Overview
//!
//! The connection is pure: the caller moves bytes between it and a socket.
//!
//! 1. Bytes from the socket go in through the TLS input.
//! 2. Bytes for the socket come out of the TLS output, whenever it is not empty.
//! 3. Application data goes in as plaintext and comes out decrypted.
//!
//! The handshake decides the keys; this layer frames, protects, and dispatches records.
//! Plaintext written before the handshake ends waits, and leaves once it does.

use std::{collections::VecDeque, mem};

use crate::{
    Alert, ClientConfig, Handshake, Level, ProtocolError, Randomness, ServerConfig, TlsError,
    TlsOutput, TrafficSecret, Verifier,
    message::KeyUpdate,
    record::{
        ContentType, INITIAL_RECORD_VERSION, LEGACY_RECORD_VERSION, MAX_PLAINTEXT, Protection,
        RawRecord,
    },
};

/// Records sealed under one AES-GCM key before the sender moves to its next key.
///
/// RFC 8446, section 5.5: at most 2^24.5 full-size records per AES-GCM key.
const KEY_UPDATE_AFTER: u64 = 1 << 24;

/// The alert level of a warning, per RFC 5246, section 7.2.
const WARNING: u8 = 1;

/// The alert level of a fatal alert.
const FATAL: u8 = 2;

/// One TLS endpoint over a byte stream.
#[derive(Debug)]
pub struct Connection<V: Verifier> {
    /// The handshake, which decides the keys.
    handshake: Handshake<V>,
    /// Whether this side is the client.
    client: bool,
    /// Bytes received and not yet cut into records.
    incoming: Vec<u8>,
    /// Records ready to send.
    outgoing: Vec<u8>,
    /// Application data received and not yet read.
    received: VecDeque<u8>,
    /// Application data written before the handshake ended.
    queued: Vec<u8>,
    /// The protection of the records read now; none before the first key.
    read: Option<Protection>,
    /// The level the records read now belong to.
    read_level: Level,
    /// TLS 1.3 read keys installed for levels the handshake has not reached.
    pending_read: Vec<(Level, Protection)>,
    /// The TLS 1.2 read key, waiting for the peer's ChangeCipherSpec.
    pending_read_tls12: Option<Protection>,
    /// The TLS 1.2 write key, waiting for this side's ChangeCipherSpec.
    pending_write_tls12: Option<Protection>,
    /// The write protection of each level; the Initial level stays in plaintext.
    write: [Option<Protection>; 3],
    /// The TLS 1.3 application secrets, which key updates advance.
    application: Option<(TrafficSecret, TrafficSecret)>,
    /// Whether any record went out yet.
    sent_any: bool,
    /// Whether the peer sent close_notify.
    peer_closed: bool,
    /// Whether this side sent close_notify.
    closed: bool,
    /// The first failure; every later call returns it again.
    error: Option<TlsError<V::Error>>,
}

impl<V: Verifier> Connection<V> {
    /// A client connection; its ClientHello waits in the TLS output.
    #[must_use]
    pub fn client(
        config: ClientConfig,
        verifier: V,
        randomness: Randomness,
        now_unix_secs: u64,
    ) -> Self {
        let handshake = Handshake::client(config, verifier, randomness, now_unix_secs);
        let mut connection = Self::new(handshake, true);
        // Only the ClientHello is queued, which cannot fail to frame.
        let _ = connection.drain_outputs();
        connection
    }

    /// A server connection, waiting for a ClientHello.
    ///
    /// A verifier is needed only when the configuration requires a client certificate.
    #[must_use]
    pub fn server(
        config: ServerConfig,
        verifier: Option<V>,
        randomness: Randomness,
        now_unix_secs: u64,
    ) -> Self {
        Self::new(
            Handshake::server(config, verifier, randomness, now_unix_secs),
            false,
        )
    }

    /// The handshake, for what it negotiated and authenticated.
    #[must_use]
    pub const fn handshake(&self) -> &Handshake<V> {
        &self.handshake
    }

    /// Whether the handshake is still running.
    #[must_use]
    pub const fn is_handshaking(&self) -> bool {
        self.handshake.is_handshaking()
    }

    /// Whether records wait to be sent.
    #[must_use]
    pub fn wants_write(&self) -> bool {
        !self.outgoing.is_empty()
    }

    /// Whether the peer closed its side with close_notify.
    #[must_use]
    pub const fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// Takes every byte waiting to be sent.
    pub fn take_tls(&mut self) -> Vec<u8> {
        mem::take(&mut self.outgoing)
    }

    /// Feeds bytes read from the socket.
    ///
    /// # Errors
    ///
    /// Fails on any protocol violation, a refused certificate, or a fatal alert from the peer.
    /// A fatal alert to the peer then waits in the TLS output, and every later call fails the same way.
    pub fn read_tls(&mut self, bytes: &[u8]) -> Result<(), TlsError<V::Error>> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        self.incoming.extend_from_slice(bytes);
        let result = self.process();
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }

    /// Queues application data, sent at once if the handshake is over.
    ///
    /// # Errors
    ///
    /// Fails after a failure or after this side closed.
    pub fn write_plaintext(&mut self, data: &[u8]) -> Result<(), TlsError<V::Error>> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        if self.closed {
            return Err(ProtocolError::DataAfterClose.into());
        }
        if self.is_handshaking() {
            self.queued.extend_from_slice(data);
            return Ok(());
        }
        let result = self.send_application(data);
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }

    /// Moves decrypted application data into a buffer.
    ///
    /// # Returns
    ///
    /// The bytes moved; zero when none are waiting.
    pub fn read_plaintext(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.received.len());
        for (slot, byte) in out.iter_mut().zip(self.received.drain(..count)) {
            *slot = byte;
        }
        count
    }

    /// Whether decrypted application data waits to be read.
    #[must_use]
    pub fn has_plaintext(&self) -> bool {
        !self.received.is_empty()
    }

    /// Sends close_notify; no application data may follow.
    pub fn close(&mut self) {
        if !self.closed && self.error.is_none() {
            self.closed = true;
            let _ = self.send_alert(WARNING, Alert::CLOSE_NOTIFY);
        }
    }

    /// A connection around a handshake.
    fn new(handshake: Handshake<V>, client: bool) -> Self {
        Self {
            handshake,
            client,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            received: VecDeque::new(),
            queued: Vec::new(),
            read: None,
            read_level: Level::Initial,
            pending_read: Vec::new(),
            pending_read_tls12: None,
            pending_write_tls12: None,
            write: [None, None, None],
            application: None,
            sent_any: false,
            peer_closed: false,
            closed: false,
            error: None,
        }
    }

    /// Records a failure and queues the fatal alert that reports it.
    fn fail(&mut self, error: TlsError<V::Error>) {
        if !matches!(
            error,
            TlsError::Protocol(ProtocolError::AlertReceived(_) | ProtocolError::DataAfterClose)
        ) {
            let _ = self.send_alert(FATAL, error.alert());
        }
        self.error = Some(error);
    }

    /// Cuts and handles every whole record received.
    fn process(&mut self) -> Result<(), TlsError<V::Error>> {
        while let Some(record) = RawRecord::take(&mut self.incoming)? {
            if self.peer_closed {
                return Err(ProtocolError::DataAfterClose.into());
            }
            self.handle_record(record)?;
        }
        Ok(())
    }

    /// Opens one record and dispatches its content.
    fn handle_record(&mut self, record: RawRecord) -> Result<(), TlsError<V::Error>> {
        let RawRecord {
            header,
            mut fragment,
        } = record;
        let kind = ContentType(header[0]);

        // RFC 8446, section 5: a ChangeCipherSpec of 0x01 is dropped during a TLS 1.3 handshake.
        // In TLS 1.2 it switches the read side to the pending keys.
        if kind == ContentType::CHANGE_CIPHER_SPEC {
            if fragment != [1] {
                return Err(ProtocolError::UnexpectedRecord(kind.0).into());
            }
            if let Some(protection) = self.pending_read_tls12.take() {
                self.read = Some(protection);
                self.read_level = Level::Application;
                return Ok(());
            }
            if self.is_handshaking() && !self.handshake.is_tls12() {
                return Ok(());
            }
            return Err(ProtocolError::UnexpectedRecord(kind.0).into());
        }

        let kind = match &mut self.read {
            None => {
                if kind == ContentType::APPLICATION_DATA {
                    return Err(ProtocolError::UnexpectedRecord(kind.0).into());
                }
                kind
            }
            Some(protection) => {
                // TLS 1.3 hides every protected record behind the application_data type.
                if !self.handshake.is_tls12() && kind != ContentType::APPLICATION_DATA {
                    return Err(ProtocolError::UnexpectedRecord(kind.0).into());
                }
                let inner = protection.open(&header, &mut fragment)?;
                if fragment.len() > MAX_PLAINTEXT {
                    return Err(ProtocolError::RecordOverflow {
                        length: fragment.len(),
                        max: MAX_PLAINTEXT,
                    }
                    .into());
                }
                inner
            }
        };

        match kind {
            ContentType::HANDSHAKE => self.handle_handshake(&fragment),
            ContentType::ALERT => self.handle_alert(&fragment),
            ContentType::APPLICATION_DATA if !self.is_handshaking() && self.read.is_some() => {
                self.received.extend(fragment);
                Ok(())
            }
            other => Err(ProtocolError::UnexpectedRecord(other.0).into()),
        }
    }

    /// Feeds handshake bytes to the handshake, then applies what it asks for.
    fn handle_handshake(&mut self, fragment: &[u8]) -> Result<(), TlsError<V::Error>> {
        if fragment.is_empty() {
            return Err(ProtocolError::EmptyRecord(ContentType::HANDSHAKE.0).into());
        }
        self.handshake.read_handshake(self.read_level, fragment)?;
        self.drain_outputs()?;

        // TLS 1.3 reads move to a new key as soon as the handshake does.
        let wanted = self.handshake.read_level();
        if !self.handshake.is_tls12() && wanted != self.read_level {
            let position = self
                .pending_read
                .iter()
                .position(|(level, _)| *level == wanted)
                .ok_or(ProtocolError::UnexpectedRecord(ContentType::HANDSHAKE.0))?;
            let (_, protection) = self.pending_read.remove(position);
            self.read = Some(protection);
            self.read_level = wanted;
        }
        if !self.is_handshaking() && !self.queued.is_empty() {
            let queued = mem::take(&mut self.queued);
            self.send_application(&queued)?;
        }
        Ok(())
    }

    /// Handles an alert: close_notify ends the peer's data, warnings pass, anything else is fatal.
    fn handle_alert(&mut self, fragment: &[u8]) -> Result<(), TlsError<V::Error>> {
        let [level, description] = fragment else {
            return Err(ProtocolError::InvalidAlert.into());
        };
        let alert = Alert(*description);
        if alert == Alert::CLOSE_NOTIFY {
            self.peer_closed = true;
            return Ok(());
        }
        // RFC 8446, section 6.1: user_canceled precedes a close; TLS 1.2 warnings carry no harm.
        let tls12_warning = self.handshake.is_tls12() && *level == WARNING;
        if alert == Alert::USER_CANCELED || tls12_warning {
            return Ok(());
        }
        Err(ProtocolError::AlertReceived(alert).into())
    }

    /// Applies every queued handshake output, in order.
    fn drain_outputs(&mut self) -> Result<(), TlsError<V::Error>> {
        while let Some(output) = self.handshake.poll_output() {
            match output {
                TlsOutput::Handshake { level, bytes } => {
                    self.send(level, ContentType::HANDSHAKE, &bytes)?;
                }
                TlsOutput::Keys { level, secrets } => {
                    self.write[Self::index(level)] = Some(Protection::tls13(&secrets.local));
                    self.pending_read
                        .push((level, Protection::tls13(&secrets.remote)));
                    if level == Level::Application {
                        self.application = Some((secrets.local, secrets.remote));
                    }
                }
                TlsOutput::ChangeCipherSpec => {
                    self.outgoing.extend(RawRecord::plaintext(
                        ContentType::CHANGE_CIPHER_SPEC,
                        LEGACY_RECORD_VERSION,
                        &[1],
                    ));
                    if let Some(protection) = self.pending_write_tls12.take() {
                        self.write[Self::index(Level::Application)] = Some(protection);
                    }
                }
                TlsOutput::Tls12Keys(secrets) => {
                    self.pending_write_tls12 = Some(Protection::tls12(&secrets.local));
                    self.pending_read_tls12 = Some(Protection::tls12(&secrets.remote));
                }
                TlsOutput::PeerKeyUpdate { update_requested } => {
                    self.update_read_key()?;
                    if update_requested {
                        self.update_write_key()?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Moves the read side to the peer's next application secret, per RFC 8446, section 7.2.
    fn update_read_key(&mut self) -> Result<(), TlsError<V::Error>> {
        let (_, remote) = self
            .application
            .as_mut()
            .ok_or(ProtocolError::UnexpectedRecord(ContentType::HANDSHAKE.0))?;
        *remote = remote.derive(b"traffic upd");
        self.read = Some(Protection::tls13(remote));
        Ok(())
    }

    /// Sends a KeyUpdate under the current key, then moves the write side to the next secret.
    fn update_write_key(&mut self) -> Result<(), TlsError<V::Error>> {
        let message = KeyUpdate {
            update_requested: false,
        }
        .encode();
        self.send(Level::Application, ContentType::HANDSHAKE, &message)?;
        let (local, _) = self
            .application
            .as_mut()
            .ok_or(ProtocolError::UnexpectedRecord(ContentType::HANDSHAKE.0))?;
        *local = local.derive(b"traffic upd");
        self.write[Self::index(Level::Application)] = Some(Protection::tls13(local));
        Ok(())
    }

    /// Sends application data, moving to a fresh TLS 1.3 key before the AES-GCM limit.
    fn send_application(&mut self, data: &[u8]) -> Result<(), TlsError<V::Error>> {
        for chunk in data.chunks(MAX_PLAINTEXT) {
            let used = self.write[Self::index(Level::Application)]
                .as_ref()
                .map_or(0, Protection::sequence);
            if self.application.is_some() && used >= KEY_UPDATE_AFTER {
                self.update_write_key()?;
            }
            self.send(Level::Application, ContentType::APPLICATION_DATA, chunk)?;
        }
        Ok(())
    }

    /// Sends an alert under the highest key in place.
    fn send_alert(&mut self, level: u8, alert: Alert) -> Result<(), TlsError<V::Error>> {
        let at = [Level::Application, Level::Handshake]
            .into_iter()
            .find(|&at| self.write[Self::index(at)].is_some())
            .unwrap_or(Level::Initial);
        self.send(at, ContentType::ALERT, &[level, alert.0])
    }

    /// Frames content of a type into records at a level, protected when the level has keys.
    fn send(
        &mut self,
        level: Level,
        kind: ContentType,
        content: &[u8],
    ) -> Result<(), TlsError<V::Error>> {
        for chunk in content.chunks(MAX_PLAINTEXT) {
            let record = match &mut self.write[Self::index(level)] {
                Some(protection) => protection.seal(kind, chunk)?,
                None => {
                    let version = if self.client && !self.sent_any {
                        INITIAL_RECORD_VERSION
                    } else {
                        LEGACY_RECORD_VERSION
                    };
                    RawRecord::plaintext(kind, version, chunk)
                }
            };
            self.sent_any = true;
            self.outgoing.extend(record);
        }
        Ok(())
    }

    /// The slot of a level in the write keys.
    const fn index(level: Level) -> usize {
        match level {
            Level::Initial => 0,
            Level::Handshake => 1,
            Level::Application => 2,
        }
    }
}
