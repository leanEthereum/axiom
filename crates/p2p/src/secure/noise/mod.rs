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
//! ```text
//! initiator                                         responder
//!   ── e ─────────────────────────────────────────────▶          message 1
//!   ◀──────────────────────── e, ee, s, es, payload ───          message 2
//!   ── s, se, payload ────────────────────────────────▶          message 3
//!
//! every message travels as [ length: u16 BE ][ bytes ]
//! ```
//!
//! The Noise static key is not the libp2p identity key.
//! Each payload therefore carries the identity key and a signature binding the two.
//!
//! ```text
//! signed message = "noise-libp2p-static-key:" || static DH public key
//! ```
//!
//! # Extension point
//!
//! The DH and AEAD primitives sit behind one trait, the identity signature behind another.
//! SHA-256 is used directly, since the protocol name pins it.
//! Supplying X25519, ChaCha20-Poly1305, and secp256k1 makes this the production `/noise`.
//!
//! See `libp2p/specs/noise/README.md` and the Noise Protocol Framework, revision 34.

mod handshake;
mod payload;
mod symmetric;
mod transport;

use std::{fmt, sync::Arc};

pub use handshake::NoiseHandshake;
pub use payload::{NoiseExtensions, NoiseHandshakePayload};

use super::{Handshake, Role, SecureError, SecurityUpgrade};
use crate::identity::{PeerId, PublicKey};

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

/// An X25519 key pair.
///
/// Implementations of the primitives should wipe the secret on drop.
#[derive(Clone)]
pub struct DhKeypair {
    /// The secret scalar.
    pub secret: [u8; 32],
    /// The public point.
    pub public: [u8; DH_LEN],
}

impl fmt::Debug for DhKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret.
        f.debug_struct("DhKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// The Diffie-Hellman and AEAD primitives of the cipher suite.
///
/// For the production suite, these are X25519 and ChaCha20-Poly1305 from RFC 7748 and RFC 8439.
pub trait NoiseCrypto: Send + Sync + fmt::Debug {
    /// A fresh key pair from a cryptographically secure source.
    fn generate_keypair(&self) -> DhKeypair;

    /// The shared secret of a local secret and a remote public key.
    ///
    /// # Errors
    ///
    /// Fails on an all-zero output, which a low-order remote point produces.
    fn dh(&self, secret: &[u8; 32], public: &[u8; DH_LEN]) -> Result<[u8; 32], SecureError>;

    /// Appends the ciphertext and tag of a plaintext.
    ///
    /// The 96-bit ChaCha20-Poly1305 nonce is 4 zero bytes, then the counter as 8 bytes LE.
    fn encrypt(&self, key: &[u8; 32], nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut Vec<u8>);

    /// Appends the plaintext of an authenticated ciphertext.
    ///
    /// # Errors
    ///
    /// Fails when the tag does not authenticate the ciphertext and associated data.
    fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SecureError>;
}

/// The libp2p identity key scheme: signing and verifying.
///
/// For Ethereum consensus nodes, this is secp256k1 ECDSA over SHA-256, DER-encoded.
pub trait NoiseIdentity: Send + Sync + fmt::Debug {
    /// The local identity key.
    fn public_key(&self) -> PublicKey;

    /// Signs a message with the local identity key.
    fn sign(&self, message: &[u8]) -> Vec<u8>;

    /// Whether a signature by a remote identity key verifies.
    fn verify(&self, key: &PublicKey, message: &[u8], signature: &[u8]) -> bool;
}

/// The `/noise` security protocol for one local identity.
#[derive(Debug)]
pub struct NoiseConfig {
    /// The DH and AEAD primitives.
    crypto: Arc<dyn NoiseCrypto>,
    /// The identity scheme.
    identity: Arc<dyn NoiseIdentity>,
    /// The static DH key pair, shared by every handshake.
    static_keypair: DhKeypair,
    /// The handshake payload: identity key and signature over the static key.
    payload: NoiseHandshakePayload,
}

impl NoiseConfig {
    /// A configuration with a fresh static key, signed by the identity key.
    #[must_use]
    pub fn new(crypto: Arc<dyn NoiseCrypto>, identity: Arc<dyn NoiseIdentity>) -> Self {
        let static_keypair = crypto.generate_keypair();
        // Sign once: every handshake reuses the same binding.
        let mut message = STATIC_KEY_DOMAIN.to_vec();
        message.extend_from_slice(&static_keypair.public);
        let payload = NoiseHandshakePayload {
            identity_key: Some(identity.public_key()),
            identity_sig: Some(identity.sign(&message)),
            extensions: None,
        };
        Self {
            crypto,
            identity,
            static_keypair,
            payload,
        }
    }
}

impl SecurityUpgrade for NoiseConfig {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn handshake(&self, role: Role, expected: Option<PeerId>) -> Box<dyn Handshake> {
        Box::new(NoiseHandshake::new(
            role,
            Arc::clone(&self.crypto),
            Arc::clone(&self.identity),
            self.static_keypair.clone(),
            self.payload.clone(),
            expected,
        ))
    }
}

#[cfg(test)]
pub(crate) mod mock;
