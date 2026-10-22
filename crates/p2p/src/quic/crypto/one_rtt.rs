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
    quic::packet::PacketNumber,
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

/// The payload keys of the application level and their update state.
#[derive(Debug)]
pub(crate) struct OneRttKeys {
    /// The secret of this side's current sending generation.
    local_secret: TrafficSecret,
    /// The sending key.
    local: PacketKey,
    /// The phase bit this side sends.
    local_phase: bool,
    /// The secret of the peer's current generation.
    remote_secret: TrafficSecret,
    /// The key of the peer's current generation.
    remote: PacketKey,
    /// The phase bit of the peer's current generation.
    remote_phase: bool,
    /// The key of the peer's next generation, derived ahead.
    next_remote: PacketKey,
    /// The previous generation's key, and when it is dropped.
    previous_remote: Option<(PacketKey, Duration)>,
    /// The lowest packet number received in the peer's current generation.
    first_in_phase: Option<PacketNumber>,
    /// Whether the peer acknowledged the current sending generation.
    ///
    /// No update may start until it has.
    acknowledgment: Acknowledgment,
    /// Packets sealed with the current sending key.
    sealed: u64,
    /// Payloads that failed to open, over the whole connection.
    failures: u64,
    /// The header key for sending.
    pub(crate) local_header: HeaderKey,
    /// The header key for receiving.
    pub(crate) remote_header: HeaderKey,
}

impl OneRttKeys {
    /// The first generation, from the handshake's application secrets.
    pub(crate) fn new(secrets: &Secrets) -> Self {
        let next_remote = PacketKey::new(&secrets.remote.derive(b"quic ku"));
        Self {
            local: PacketKey::new(&secrets.local),
            local_secret: secrets.local.clone(),
            local_phase: false,
            remote: PacketKey::new(&secrets.remote),
            remote_secret: secrets.remote.clone(),
            remote_phase: false,
            next_remote,
            previous_remote: None,
            first_in_phase: None,
            acknowledgment: Acknowledgment::Unused,
            sealed: 0,
            failures: 0,
            local_header: HeaderKey::new(&secrets.local),
            remote_header: HeaderKey::new(&secrets.remote),
        }
    }

    /// The phase bit to send.
    pub(crate) const fn phase(&self) -> bool {
        self.local_phase
    }

    /// Seals a payload with the current sending key.
    pub(crate) fn seal(
        &mut self,
        pn: PacketNumber,
        header: &[u8],
        payload: &mut [u8],
    ) -> [u8; TAG_LEN] {
        if self.acknowledgment == Acknowledgment::Unused {
            self.acknowledgment = Acknowledgment::Pending(pn);
        }
        self.sealed += 1;
        self.local.seal(pn, header, payload)
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
        header: &[u8],
        payload: &mut [u8],
        tag: &[u8; TAG_LEN],
        now: Duration,
        retain: Duration,
    ) -> Result<Opened, AeadError> {
        // The previous generation expires once reordered packets can no longer arrive.
        if self
            .previous_remote
            .as_ref()
            .is_some_and(|(_, until)| *until <= now)
        {
            self.previous_remote = None;
        }
        let outcome = if phase == self.remote_phase {
            self.remote
                .open(pn, header, payload, tag)
                .map(|()| Opened::Current)
        } else if let Some((previous, _)) = self
            .previous_remote
            .as_ref()
            .filter(|_| self.first_in_phase.is_some_and(|first| pn < first))
        {
            // A packet older than the current phase began: it belongs to the previous one.
            previous
                .open(pn, header, payload, tag)
                .map(|()| Opened::Current)
        } else {
            self.next_remote
                .open(pn, header, payload, tag)
                .map(|()| Opened::Updated)
        };
        match outcome {
            Ok(Opened::Updated) => self.advance_remote(pn, now + retain),
            Ok(Opened::Current) => {
                if phase == self.remote_phase && self.first_in_phase.is_none_or(|first| pn < first)
                {
                    self.first_in_phase = Some(pn);
                }
            }
            Err(AeadError) => self.failures += 1,
        }
        outcome
    }

    /// Moves to the peer's next generation, and this side's too if it has not already.
    fn advance_remote(&mut self, pn: PacketNumber, drop_previous_at: Duration) {
        let next_secret = self.remote_secret.derive(b"quic ku");
        let after_next = PacketKey::new(&next_secret.derive(b"quic ku"));
        let current = mem::replace(&mut self.next_remote, after_next);
        let previous = mem::replace(&mut self.remote, current);
        self.previous_remote = Some((previous, drop_previous_at));
        self.remote_secret = next_secret;
        self.remote_phase = !self.remote_phase;
        self.first_in_phase = Some(pn);
        // The peer started the update: answer it by updating the sending side too.
        if self.local_phase != self.remote_phase {
            self.advance_local();
        }
    }

    /// Moves this side's sending key to the next generation.
    fn advance_local(&mut self) {
        self.local_secret = self.local_secret.derive(b"quic ku");
        self.local = PacketKey::new(&self.local_secret);
        self.local_phase = !self.local_phase;
        self.acknowledgment = Acknowledgment::Unused;
        self.sealed = 0;
    }

    /// Notes that the peer acknowledged packets up to a number.
    pub(crate) fn on_acked(&mut self, largest: PacketNumber) {
        if let Acknowledgment::Pending(first) = self.acknowledgment
            && largest >= first
        {
            self.acknowledgment = Acknowledgment::Confirmed;
        }
    }

    /// Starts an update when the sending key nears its confidentiality limit.
    ///
    /// An update needs the handshake confirmed and the current generation acknowledged.
    pub(crate) fn update_if_due(&mut self) -> bool {
        let limit = confidentiality_limit(self.local_secret.suite());
        // Threshold: update at three quarters of the limit, leaving room for the confirmation.
        if self.sealed < limit / 4 * 3 || !self.can_update() {
            return false;
        }
        self.advance_local();
        true
    }

    /// Starts an update now, if the rules of RFC 9001, section 6.1, allow one.
    pub(crate) fn force_update(&mut self) -> bool {
        if !self.can_update() {
            return false;
        }
        self.advance_local();
        true
    }

    /// Whether this side may start an update.
    fn can_update(&self) -> bool {
        self.local_phase == self.remote_phase && self.acknowledgment == Acknowledgment::Confirmed
    }

    /// Whether the failed decryptions reached the integrity limit.
    pub(crate) fn integrity_exhausted(&self) -> bool {
        self.failures >= integrity_limit(self.remote_secret.suite())
    }

    /// Whether the sending key reached its confidentiality limit without an update.
    pub(crate) fn confidentiality_exhausted(&self) -> bool {
        self.sealed >= confidentiality_limit(self.local_secret.suite())
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

    /// Seals one payload on one side and opens it on the other.
    fn deliver(from: &mut OneRttKeys, to: &mut OneRttKeys, pn: u64) -> Result<Opened, AeadError> {
        let mut payload = *b"data";
        let phase = from.phase();
        let tag = from.seal(PacketNumber(pn), b"h", &mut payload);
        to.open(
            PacketNumber(pn),
            phase,
            b"h",
            &mut payload,
            &tag,
            Duration::from_secs(1),
            Duration::from_secs(3),
        )
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
        assert_eq!(client.local_phase, client.remote_phase);
    }

    #[test]
    fn reordered_packet_of_the_previous_phase_still_opens() {
        let (mut client, mut server) = pair(CipherSuite::ChaCha20Poly1305Sha256);

        // Packet 5 is sealed in phase 0 but delayed.
        let mut late = *b"late";
        let late_tag = client.seal(PacketNumber(5), b"h", &mut late);
        client.on_acked(PacketNumber(5));
        assert!(client.force_update());
        assert_eq!(deliver(&mut client, &mut server, 6), Ok(Opened::Updated));

        // Packet 5 carries phase 0 and a lower number, so the previous key opens it.
        let opened = server.open(
            PacketNumber(5),
            false,
            b"h",
            &mut late,
            &late_tag,
            Duration::from_secs(2),
            Duration::from_secs(3),
        );
        assert_eq!(opened, Ok(Opened::Current));
        assert_eq!(&late, b"late");
    }

    #[test]
    fn forged_flip_changes_nothing() {
        let (_, mut server) = pair(CipherSuite::Aes128GcmSha256);
        let mut payload = *b"junk";
        let opened = server.open(
            PacketNumber(3),
            true,
            b"h",
            &mut payload,
            &[0; TAG_LEN],
            Duration::ZERO,
            Duration::from_secs(3),
        );
        assert_eq!(opened, Err(AeadError));
        assert!(!server.phase());
        assert_eq!(server.failures, 1);
    }
}
