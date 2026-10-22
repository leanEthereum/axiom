//! 1-RTT keys and their updates, per RFC 9001, section 6.
//!
//! # Overview
//!
//! The key phase bit of a short header names the generation of the payload key.
//! Either side may move to the next generation by flipping the bit on what it sends.
//! The peer notices the flip, derives the next keys, and answers with the flipped bit.
//!
//! Each generation's secret comes from the previous one:
//!
//! ```text
//! secret_{n+1} = HKDF-Expand-Label(secret_n, "quic ku", "", 32)
//! ```
//!
//! Header protection keys never change.
//!
//! The receiving side keeps three payload keys:
//!
//! - the current one, matching the peer's current phase
//! - the next one, derived ahead so a flipped packet is opened without delay
//! - the previous one, for a short while, so reordered packets still open
//!
//! A flipped packet that fails to open changes nothing: an attacker cannot force an update.

use std::{mem, time::Duration};

use axiom_crypto::AeadError;

use super::{HeaderKey, PacketKey, TAG_LEN};
use crate::{
    quic::{
        DecodeError,
        packet::{PacketNumber, PlainPacket},
    },
    tls::{CipherSuite, Secrets, TrafficSecret},
};

/// Packets a key may protect, per RFC 9001, section 6.6.
///
/// Threshold: this side updates its keys well before the limit.
const fn confidentiality_limit(suite: CipherSuite) -> u64 {
    match suite {
        // 2^23 for AES-GCM.
        CipherSuite::Aes128GcmSha256 => 1 << 23,
        // ChaCha20-Poly1305 has no practical limit below the packet number space.
        CipherSuite::ChaCha20Poly1305Sha256 => 1 << 62,
    }
}

/// Failed decryptions a connection tolerates over its life, per RFC 9001, section 6.6.
const fn integrity_limit(suite: CipherSuite) -> u64 {
    match suite {
        // 2^52 for AES-GCM.
        CipherSuite::Aes128GcmSha256 => 1 << 52,
        // 2^36 for ChaCha20-Poly1305.
        CipherSuite::ChaCha20Poly1305Sha256 => 1 << 36,
    }
}

/// The outcome of opening a short-header payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Opened {
    /// The payload opened under the current or previous keys.
    Current,
    /// The payload opened under the next keys: the peer updated, and so did this side.
    Updated,
}

/// A received payload with its header and tag, to open in place.
#[derive(Debug)]
pub(crate) struct Protected<'a> {
    /// The unprotected header, the associated data.
    pub(crate) header: &'a [u8],
    /// The ciphertext, decrypted in place.
    pub(crate) payload: &'a mut [u8],
    /// The tag.
    pub(crate) tag: &'a [u8; TAG_LEN],
}

/// How far the peer has acknowledged the current sending generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Acknowledgment {
    /// Nothing was sent under it yet.
    Unused,
    /// Packets were sent from this number on, none acknowledged.
    Pending(PacketNumber),
    /// The peer acknowledged a packet of this generation.
    Confirmed,
}

/// This side's sending generation.
#[derive(Debug)]
struct SendGeneration {
    /// The generation's secret.
    secret: TrafficSecret,
    /// The payload key.
    key: PacketKey,
    /// The phase bit sent.
    phase: bool,
    /// Whether the peer acknowledged the generation; no update may start before.
    acknowledgment: Acknowledgment,
    /// Packets sealed under the key.
    sealed: u64,
}

impl SendGeneration {
    /// The first generation.
    fn new(secret: &TrafficSecret) -> Self {
        Self {
            key: PacketKey::new(secret),
            secret: secret.clone(),
            phase: false,
            acknowledgment: Acknowledgment::Unused,
            sealed: 0,
        }
    }

    /// Seals a payload, counting it against the key.
    fn seal(&mut self, pn: PacketNumber, header: &[u8], payload: &mut [u8]) -> [u8; TAG_LEN] {
        if self.acknowledgment == Acknowledgment::Unused {
            self.acknowledgment = Acknowledgment::Pending(pn);
        }
        self.sealed += 1;
        self.key.seal(pn, header, payload)
    }

    /// Moves to the next generation.
    fn advance(&mut self) {
        self.secret = self.secret.derive(b"quic ku");
        self.key = PacketKey::new(&self.secret);
        self.phase = !self.phase;
        self.acknowledgment = Acknowledgment::Unused;
        self.sealed = 0;
    }
}

/// The peer's generations, as this side opens them.
#[derive(Debug)]
struct ReceiveGenerations {
    /// The secret of the peer's current generation.
    secret: TrafficSecret,
    /// The key of the current generation.
    current: PacketKey,
    /// The phase bit of the current generation.
    phase: bool,
    /// The next generation's key, derived ahead.
    next: PacketKey,
    /// The previous generation's key, and when it is dropped.
    previous: Option<(PacketKey, Duration)>,
    /// The lowest packet number received in the current generation.
    first_in_phase: Option<PacketNumber>,
    /// Payloads that failed to open, over the whole connection.
    failures: u64,
}

impl ReceiveGenerations {
    /// The first generation.
    fn new(secret: &TrafficSecret) -> Self {
        Self {
            current: PacketKey::new(secret),
            next: PacketKey::new(&secret.derive(b"quic ku")),
            secret: secret.clone(),
            phase: false,
            previous: None,
            first_in_phase: None,
            failures: 0,
        }
    }

    /// Opens a payload under the generation its phase bit and number point to.
    fn open(
        &mut self,
        pn: PacketNumber,
        phase: bool,
        packet: Protected<'_>,
        now: Duration,
        retain: Duration,
    ) -> Result<Opened, AeadError> {
        // The previous generation expires once reordered packets can no longer arrive.
        if self
            .previous
            .as_ref()
            .is_some_and(|(_, until)| *until <= now)
        {
            self.previous = None;
        }
        let Protected {
            header,
            payload,
            tag,
        } = packet;
        let outcome = if phase == self.phase {
            self.current
                .open(pn, header, payload, tag)
                .map(|()| Opened::Current)
        } else if let Some((previous, _)) = self
            .previous
            .as_ref()
            .filter(|_| self.first_in_phase.is_some_and(|first| pn < first))
        {
            // A packet older than the current phase began: it belongs to the previous one.
            previous
                .open(pn, header, payload, tag)
                .map(|()| Opened::Current)
        } else {
            self.next
                .open(pn, header, payload, tag)
                .map(|()| Opened::Updated)
        };
        match outcome {
            Ok(Opened::Updated) => self.advance(pn, now + retain),
            Ok(Opened::Current) => {
                if phase == self.phase && self.first_in_phase.is_none_or(|first| pn < first) {
                    self.first_in_phase = Some(pn);
                }
            }
            Err(AeadError) => self.failures += 1,
        }
        outcome
    }

    /// Moves to the next generation, keeping the current key as the previous one for a while.
    fn advance(&mut self, pn: PacketNumber, drop_previous_at: Duration) {
        self.secret = self.secret.derive(b"quic ku");
        let after_next = PacketKey::new(&self.secret.derive(b"quic ku"));
        let current = mem::replace(&mut self.next, after_next);
        let previous = mem::replace(&mut self.current, current);
        self.previous = Some((previous, drop_previous_at));
        self.phase = !self.phase;
        self.first_in_phase = Some(pn);
    }
}

/// The payload keys of the application level and their update state.
#[derive(Debug)]
pub(crate) struct OneRttKeys {
    /// This side's sending generation.
    send: SendGeneration,
    /// The peer's generations.
    receive: ReceiveGenerations,
    /// The header key for sending.
    local_header: HeaderKey,
    /// The header key for receiving.
    pub(crate) remote_header: HeaderKey,
}

impl OneRttKeys {
    /// The first generation, from the handshake's application secrets.
    pub(crate) fn new(secrets: &Secrets) -> Self {
        Self {
            send: SendGeneration::new(&secrets.local),
            receive: ReceiveGenerations::new(&secrets.remote),
            local_header: HeaderKey::new(&secrets.local),
            remote_header: HeaderKey::new(&secrets.remote),
        }
    }

    /// The phase bit to send.
    pub(crate) const fn phase(&self) -> bool {
        self.send.phase
    }

    /// Seals a short-header packet into a datagram.
    pub(crate) fn seal_packet(
        &mut self,
        packet: PlainPacket,
        out: &mut Vec<u8>,
    ) -> Result<(), DecodeError> {
        let send = &mut self.send;
        packet.seal(
            |pn, header, payload| send.seal(pn, header, payload),
            &self.local_header,
            out,
        )
    }

    /// Opens a payload under the generation its phase bit names.
    ///
    /// # Arguments
    ///
    /// - `phase`: the key phase bit of the unprotected header.
    /// - `now`: the connection clock.
    /// - `retain`: how long the previous generation stays usable, three probe timeouts.
    pub(crate) fn open(
        &mut self,
        pn: PacketNumber,
        phase: bool,
        packet: Protected<'_>,
        now: Duration,
        retain: Duration,
    ) -> Result<Opened, AeadError> {
        let outcome = self.receive.open(pn, phase, packet, now, retain);
        // The peer started an update: answer it by updating the sending side too.
        if outcome == Ok(Opened::Updated) && self.send.phase != self.receive.phase {
            self.send.advance();
        }
        outcome
    }

    /// Notes that the peer acknowledged packets up to a number.
    pub(crate) fn on_acked(&mut self, largest: PacketNumber) {
        if let Acknowledgment::Pending(first) = self.send.acknowledgment
            && largest >= first
        {
            self.send.acknowledgment = Acknowledgment::Confirmed;
        }
    }

    /// Starts an update when the sending key nears its confidentiality limit.
    pub(crate) fn update_if_due(&mut self) -> bool {
        let limit = confidentiality_limit(self.send.secret.suite());
        // Threshold: update at three quarters of the limit, leaving room for the confirmation.
        if self.send.sealed < limit / 4 * 3 {
            return false;
        }
        self.force_update()
    }

    /// Starts an update now, if the rules of RFC 9001, section 6.1, allow one.
    ///
    /// The peer must have acknowledged the current generation, and answered any update in progress.
    pub(crate) fn force_update(&mut self) -> bool {
        if self.send.phase != self.receive.phase
            || self.send.acknowledgment != Acknowledgment::Confirmed
        {
            return false;
        }
        self.send.advance();
        true
    }

    /// Whether the failed decryptions reached the integrity limit.
    pub(crate) const fn integrity_exhausted(&self) -> bool {
        self.receive.failures >= integrity_limit(self.receive.secret.suite())
    }

    /// Whether the sending key reached its confidentiality limit without an update.
    pub(crate) const fn confidentiality_exhausted(&self) -> bool {
        self.send.sealed >= confidentiality_limit(self.send.secret.suite())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Matching key sets for a client and a server.
    fn pair(suite: CipherSuite) -> (OneRttKeys, OneRttKeys) {
        let client_secret = TrafficSecret::new(suite, [1; 32]);
        let server_secret = TrafficSecret::new(suite, [2; 32]);
        let client = OneRttKeys::new(&Secrets {
            local: client_secret.clone(),
            remote: server_secret.clone(),
        });
        let server = OneRttKeys::new(&Secrets {
            local: server_secret,
            remote: client_secret,
        });
        (client, server)
    }

    /// Opens a payload at one second, keeping previous keys for three.
    fn open(
        keys: &mut OneRttKeys,
        pn: u64,
        phase: bool,
        payload: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<Opened, AeadError> {
        let packet = Protected {
            header: b"h",
            payload,
            tag,
        };
        keys.open(
            PacketNumber(pn),
            phase,
            packet,
            Duration::from_secs(1),
            Duration::from_secs(3),
        )
    }

    /// Seals one payload on one side and opens it on the other.
    fn deliver(from: &mut OneRttKeys, to: &mut OneRttKeys, pn: u64) -> Result<Opened, AeadError> {
        let mut payload = *b"data";
        let phase = from.phase();
        let tag = from.send.seal(PacketNumber(pn), b"h", &mut payload);
        open(to, pn, phase, &mut payload, &tag)
    }

    #[test]
    fn peer_initiated_update_flips_both_directions() {
        let (mut client, mut server) = pair(CipherSuite::Aes128GcmSha256);
        assert_eq!(deliver(&mut client, &mut server, 0), Ok(Opened::Current));
        assert_eq!(deliver(&mut server, &mut client, 0), Ok(Opened::Current));

        // The client may update only after the server acknowledged packet 0.
        assert!(!client.force_update());
        client.on_acked(PacketNumber(0));
        assert!(client.force_update());
        assert!(client.phase());

        // The server sees the flipped bit, opens with the next key, and flips its own.
        assert_eq!(deliver(&mut client, &mut server, 1), Ok(Opened::Updated));
        assert!(server.phase());

        // The client receives the server's flipped packet under its already-derived next key.
        assert_eq!(deliver(&mut server, &mut client, 1), Ok(Opened::Updated));
        assert_eq!(client.send.phase, client.receive.phase);

        // Until the server acknowledges a phase 1 packet, no further update may start.
        assert!(!client.force_update());
    }

    #[test]
    fn reordered_packet_of_the_previous_phase_still_opens() {
        let (mut client, mut server) = pair(CipherSuite::ChaCha20Poly1305Sha256);

        // Packet 5 is sealed in phase 0 but delayed.
        let mut late = *b"late";
        let late_tag = client.send.seal(PacketNumber(5), b"h", &mut late);
        client.on_acked(PacketNumber(5));
        assert!(client.force_update());
        assert_eq!(deliver(&mut client, &mut server, 6), Ok(Opened::Updated));

        // Packet 5 carries phase 0 and a lower number, so the previous key opens it.
        assert_eq!(
            open(&mut server, 5, false, &mut late, &late_tag),
            Ok(Opened::Current)
        );
        assert_eq!(&late, b"late");
    }

    #[test]
    fn forged_flip_changes_nothing() {
        let (_, mut server) = pair(CipherSuite::Aes128GcmSha256);
        let mut payload = *b"junk";
        assert_eq!(
            open(&mut server, 3, true, &mut payload, &[0; TAG_LEN]),
            Err(AeadError)
        );
        assert!(!server.phase());
        assert_eq!(server.receive.failures, 1);
    }
}
