//! noise-libp2p: the Noise XX handshake with libp2p identity binding.
//!
//! # Overview
//!
//! The protocol name `Noise_XX_25519_ChaChaPoly_SHA256` fixes every primitive.
//!
//! - X25519 Diffie-Hellman for the ephemeral and static keys.
//! - ChaCha20-Poly1305 for encryption, with a 16-byte tag.
//! - SHA-256 for the transcript hash and the HKDF key schedule.
//!
//! The XX pattern takes three messages and authenticates both static keys.
//!
//! 1. The initiator sends e.
//! 2. The responder sends e, ee, s, es, and its payload.
//! 3. The initiator sends s, se, and its payload.
//!
//! Every message travels with a length prefix:
//!
//! ```text
//! [ length: u16 BE ][ bytes ]
//! ```
//!
//! The Noise static key is not the libp2p identity key.
//! Each payload therefore carries the identity key and a signature binding the two.
//!
//! ```text
//! signed message = "noise-libp2p-static-key:" || static DH public key
//! signature      = DER(ECDSA-secp256k1(SHA-256(signed message)))
//! ```
//!
//! # Keys
//!
//! One X25519 static key serves every connection of a node, signed once by the identity.
//! The libp2p spec allows this, and forbids storing it to disk; it lives only in memory.
//! Every handshake draws a fresh ephemeral key from a forward-secure generator.
//!
//! See `libp2p/specs/noise/README.md` and the Noise Protocol Framework, revision 34.

mod handshake;
mod payload;
mod symmetric;
mod transport;
#[cfg(test)]
mod vectors;
mod xx;

use std::{
    fmt, io,
    sync::{Mutex, PoisonError},
};

use axiom_crypto::x25519::SecretKey;
pub use handshake::NoiseHandshake;
pub use payload::{NoiseExtensions, NoiseHandshakePayload};

use super::{Handshake, Role, SecurityUpgrade};
use crate::{
    Entropy,
    identity::{Keypair, PeerId},
};

/// The multistream-select name.
pub const PROTOCOL: &str = "/noise";

/// The Noise protocol name, which seeds the transcript hash.
const PROTOCOL_NAME: &[u8; 32] = b"Noise_XX_25519_ChaChaPoly_SHA256";

/// Prefix of the message an identity key signs to vouch for a static key.
pub const STATIC_KEY_DOMAIN: &[u8] = b"noise-libp2p-static-key:";

/// Bytes of an X25519 public key.
pub const DH_LEN: usize = 32;

/// Bytes of the AEAD authentication tag.
pub const TAG_LEN: usize = 16;

/// Longest Noise message, bounded by the 2-byte length prefix.
pub const MAX_MESSAGE_LEN: usize = 65535;

/// Longest plaintext one transport message carries: the message bound minus the tag.
pub const MAX_PLAINTEXT_LEN: usize = MAX_MESSAGE_LEN - TAG_LEN;

/// The `/noise` security protocol for one local identity.
pub struct NoiseConfig {
    /// The static X25519 secret, shared by every handshake.
    static_secret: SecretKey,
    /// The handshake payload: identity key and signature over the static key.
    payload: NoiseHandshakePayload,
    /// Where ephemeral secrets come from.
    keys: Mutex<Entropy>,
}

impl fmt::Debug for NoiseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The payload is public; the secrets are not.
        f.debug_struct("NoiseConfig")
            .field("payload", &self.payload)
            .finish_non_exhaustive()
    }
}

impl NoiseConfig {
    /// A configuration with keys drawn from the operating system's entropy.
    ///
    /// # Errors
    ///
    /// Fails when the entropy device cannot be read.
    pub fn new(identity: &Keypair) -> io::Result<Self> {
        Ok(Self::with_key_source(identity, Entropy::from_os()?))
    }

    /// A configuration whose every key derives from a seed.
    ///
    /// Equal seeds give equal transcripts.
    /// Use it in tests and simulations only.
    #[must_use]
    pub fn from_seed(identity: &Keypair, seed: [u8; 32]) -> Self {
        Self::with_key_source(identity, Entropy::new(seed))
    }

    /// The payload this node sends: identity key, signature, no extensions.
    #[must_use]
    pub const fn payload(&self) -> &NoiseHandshakePayload {
        &self.payload
    }

    /// Draws the static key and signs it once: every handshake reuses the binding.
    fn with_key_source(identity: &Keypair, mut keys: Entropy) -> Self {
        let static_secret = SecretKey::from_bytes(keys.array());
        let mut message = STATIC_KEY_DOMAIN.to_vec();
        message.extend_from_slice(static_secret.public_key().as_bytes());
        let payload = NoiseHandshakePayload {
            identity_key: Some(identity.public_key().clone()),
            identity_sig: Some(identity.sign(&message).into_bytes()),
            extensions: None,
        };
        Self {
            static_secret,
            payload,
            keys: Mutex::new(keys),
        }
    }
}

impl SecurityUpgrade for NoiseConfig {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn handshake(&self, role: Role, expected: Option<PeerId>) -> Box<dyn Handshake> {
        // A panic elsewhere cannot corrupt the generator: a draw is one plain overwrite.
        let ephemeral = SecretKey::from_bytes(
            self.keys
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .array(),
        );
        Box::new(NoiseHandshake::new(
            role,
            self.static_secret.clone(),
            ephemeral,
            &self.payload,
            expected,
        ))
    }
}
