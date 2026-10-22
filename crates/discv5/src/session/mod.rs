//! Established sessions: per-direction keys that seal and open message packets.

mod cache;
mod error;
mod keys;

use std::fmt;

use axiom_crypto::aes::Aes128Gcm;
pub use cache::SessionCache;
pub use error::OpenError;
pub use keys::{ChallengeData, IdSignature, SessionKeys};

use crate::{
    message::Message,
    node_id::NodeId,
    packet::{AuthData, Header, MaskingIv, Nonce, Packet},
    rng::Csprng,
};

/// The keys of one peer relationship, and the counter that keeps nonces unique.
///
/// # Invariants
///
/// A nonce never repeats under the write key.
/// The first 32 bits count messages; the other 64 are random, per discv5-theory.md, "Session Cache".
#[derive(Clone)]
pub struct Session {
    /// Seals outgoing messages.
    write: Aes128Gcm,
    /// Opens incoming messages.
    read: Aes128Gcm,
    /// The read key of the session this one replaced, still accepted.
    ///
    /// Two nodes that challenge each other at once each finish a handshake.
    /// Each side then writes with its newest keys, which the other may hold only as the older session.
    previous_read: Option<Aes128Gcm>,
    /// Messages sealed so far.
    counter: u32,
}

impl Session {
    /// A session from explicit write and read keys.
    #[must_use]
    pub fn new(write_key: &[u8; 16], read_key: &[u8; 16]) -> Self {
        Self {
            write: Aes128Gcm::new(write_key),
            read: Aes128Gcm::new(read_key),
            previous_read: None,
            counter: 0,
        }
    }

    /// This session, still accepting messages sealed for the one it replaces.
    #[must_use]
    pub fn replacing(mut self, old: &Self) -> Self {
        // Only one generation back: older keys are dropped.
        self.previous_read = Some(old.read.clone());
        self
    }

    /// The initiator's view: it writes with the initiator key.
    #[must_use]
    pub fn initiator(keys: &SessionKeys) -> Self {
        Self::new(&keys.initiator_key, &keys.recipient_key)
    }

    /// The challenger's view: it writes with the recipient key.
    #[must_use]
    pub fn recipient(keys: &SessionKeys) -> Self {
        Self::new(&keys.recipient_key, &keys.initiator_key)
    }

    /// A fresh nonce: the message count, then 64 random bits.
    pub fn next_nonce(&mut self, rng: &mut Csprng) -> Nonce {
        // The counter wraps after 2^32 messages; the random half still separates nonces.
        self.counter = self.counter.wrapping_add(1);
        let mut nonce = [0_u8; 12];
        nonce[..4].copy_from_slice(&self.counter.to_be_bytes());
        rng.fill(&mut nonce[4..]);
        Nonce(nonce)
    }

    /// Seals a message into a packet for a destination.
    ///
    /// The caller picks the masking IV, nonce, and authdata; tests pin them to vectors.
    #[must_use]
    pub fn seal(
        &self,
        masking_iv: MaskingIv,
        nonce: Nonce,
        auth: AuthData,
        message: &Message,
        dest: &NodeId,
    ) -> Vec<u8> {
        // The additional data is the IV and unmasked header, so the header is authenticated too.
        let mut packet = Packet {
            masking_iv,
            header: Header { nonce, auth },
            message: Vec::new(),
        };
        let ad = packet.message_ad();
        packet.message = self.write.seal(&nonce.0, &ad, &message.encode());
        packet.encode(dest)
    }

    /// Opens the message of a received packet.
    ///
    /// # Errors
    ///
    /// Fails when the tag does not verify or the plaintext is not a message.
    pub fn open(&self, packet: &Packet) -> Result<Message, OpenError> {
        // The same additional data the sender authenticated, under the current key first.
        let nonce = &packet.header.nonce.0;
        let ad = packet.message_ad();
        let plaintext = self
            .read
            .open(nonce, &ad, &packet.message)
            .or_else(|error| match &self.previous_read {
                Some(previous) => previous.open(nonce, &ad, &packet.message),
                None => Err(error),
            })
            .map_err(|_| OpenError::Authentication)?;
        Message::decode(&plaintext).map_err(OpenError::Message)
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keys are secret: show only the counter.
        f.debug_struct("Session")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}
