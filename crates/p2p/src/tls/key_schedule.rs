//! The TLS 1.3 key schedule and transcript hash, per RFC 8446, sections 4.4.1 and 7.1.
//!
//! Without a pre-shared key, the schedule is a chain of three extractions.
//!
//! ```text
//! early     = HKDF-Extract(0, 0)
//! handshake = HKDF-Extract(Derive-Secret(early, "derived", ""), ECDHE)
//! master    = HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0)
//!
//! Derive-Secret(S, label, messages) = HKDF-Expand-Label(S, label, Transcript-Hash(messages), 32)
//! ```
//!
//! Each traffic secret binds the transcript up to its point, so a tampered message changes every later key.

use axiom_crypto::hkdf::Hkdf;
use sha2::{Digest, Sha256};

use super::{CipherSuite, Secrets, TrafficSecret};

/// The running SHA-256 hash of every handshake message, headers included.
#[derive(Clone, Debug, Default)]
pub(crate) struct Transcript(Sha256);

impl Transcript {
    /// An empty transcript.
    pub(crate) fn new() -> Self {
        Self(Sha256::new())
    }

    /// Appends one framed handshake message.
    pub(crate) fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    /// The hash of every message so far.
    pub(crate) fn hash(&self) -> [u8; 32] {
        self.0.clone().finalize().into()
    }
}

/// Which end of the handshake a side is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    /// The side that sends the ClientHello.
    Client,
    /// The side that answers it.
    Server,
}

/// The two traffic secrets of one level, by direction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrafficPair {
    /// Protects what the client sends.
    pub(crate) client: TrafficSecret,
    /// Protects what the server sends.
    pub(crate) server: TrafficSecret,
}

impl TrafficPair {
    /// The pair as seen by one side: its own sending secret first.
    pub(crate) fn secrets(&self, role: Role) -> Secrets {
        let (local, remote) = match role {
            Role::Client => (&self.client, &self.server),
            Role::Server => (&self.server, &self.client),
        };
        Secrets {
            local: local.clone(),
            remote: remote.clone(),
        }
    }

    /// The secret one side sends with.
    pub(crate) const fn sending(&self, role: Role) -> &TrafficSecret {
        match role {
            Role::Client => &self.client,
            Role::Server => &self.server,
        }
    }

    /// The secret one side receives with.
    pub(crate) const fn receiving(&self, role: Role) -> &TrafficSecret {
        match role {
            Role::Client => &self.server,
            Role::Server => &self.client,
        }
    }
}

/// The handshake secret, extracted from the X25519 shared secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HandshakeSecret(TrafficSecret);

impl HandshakeSecret {
    /// The handshake secret of a suite and an ECDHE shared secret.
    pub(crate) fn new(suite: CipherSuite, shared: &[u8; 32]) -> Self {
        // With no pre-shared key, the early secret extracts from zeros.
        let early = TrafficSecret::new(suite, *Hkdf::extract(&[0; 32], &[0; 32]).prk());
        let salt = Self::derived(&early);
        Self(TrafficSecret::new(
            suite,
            *Hkdf::extract(&salt, shared).prk(),
        ))
    }

    /// The handshake traffic secrets, bound to the transcript through the ServerHello.
    pub(crate) fn traffic(&self, transcript_hash: &[u8; 32]) -> TrafficPair {
        TrafficPair {
            client: Self::derive_secret(&self.0, b"c hs traffic", transcript_hash),
            server: Self::derive_secret(&self.0, b"s hs traffic", transcript_hash),
        }
    }

    /// The master secret that follows.
    pub(crate) fn master(&self) -> MasterSecret {
        let salt = Self::derived(&self.0);
        MasterSecret(TrafficSecret::new(
            self.0.suite(),
            *Hkdf::extract(&salt, &[0; 32]).prk(),
        ))
    }

    /// The secret itself.
    #[cfg(test)]
    pub(crate) const fn secret(&self) -> &TrafficSecret {
        &self.0
    }

    /// The salt of the next extraction: Derive-Secret(secret, "derived", "").
    fn derived(secret: &TrafficSecret) -> [u8; 32] {
        let empty: [u8; 32] = Sha256::digest([]).into();
        *Self::derive_secret(secret, b"derived", &empty).as_bytes()
    }

    /// Derive-Secret over a transcript hash.
    fn derive_secret(
        secret: &TrafficSecret,
        label: &[u8],
        transcript_hash: &[u8; 32],
    ) -> TrafficSecret {
        let mut out = [0; 32];
        secret.expand_label(label, transcript_hash, &mut out);
        TrafficSecret::new(secret.suite(), out)
    }
}

/// The master secret, from which the application traffic secrets derive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MasterSecret(TrafficSecret);

impl MasterSecret {
    /// The application traffic secrets, bound to the transcript through the server Finished.
    pub(crate) fn traffic(&self, transcript_hash: &[u8; 32]) -> TrafficPair {
        TrafficPair {
            client: HandshakeSecret::derive_secret(&self.0, b"c ap traffic", transcript_hash),
            server: HandshakeSecret::derive_secret(&self.0, b"s ap traffic", transcript_hash),
        }
    }

    /// The secret itself.
    #[cfg(test)]
    pub(crate) const fn secret(&self) -> &TrafficSecret {
        &self.0
    }
}
