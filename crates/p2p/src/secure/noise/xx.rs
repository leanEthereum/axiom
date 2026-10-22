//! The bare XX pattern: tokens, key mixing, and payload encryption, without libp2p.
//!
//! ```text
//! XX:
//!   -> e
//!   <- e, ee, s, es
//!   -> s, se
//! ```
//!
//! Ephemeral secrets come in from the caller, so published test vectors can pin every byte.
//! See the Noise Protocol Framework, revision 34, sections 5.3 and 7.5.

use axiom_crypto::x25519::{PublicKey, SecretKey, SharedSecret};

use super::{
    DH_LEN,
    symmetric::{CipherState, SymmetricState},
};
use crate::secure::{Role, SecureError};

/// One party's handshake state for the XX pattern.
pub(super) struct XxState {
    /// The side this party plays.
    role: Role,
    /// Transcript hash, chaining key, and handshake cipher.
    symmetric: SymmetricState,
    /// The local static secret.
    static_secret: SecretKey,
    /// The local ephemeral secret, set when this side sends its e token.
    ephemeral: Option<SecretKey>,
    /// The remote ephemeral public key.
    remote_ephemeral: Option<PublicKey>,
    /// The remote static public key, learned from its s token.
    remote_static: Option<PublicKey>,
}

impl XxState {
    /// A fresh state after the prologue.
    pub(super) fn new(role: Role, prologue: &[u8], static_secret: SecretKey) -> Self {
        Self {
            role,
            symmetric: SymmetricState::new(prologue),
            static_secret,
            ephemeral: None,
            remote_ephemeral: None,
            remote_static: None,
        }
    }

    /// The side this party plays.
    pub(super) const fn role(&self) -> Role {
        self.role
    }

    /// The remote static key, once its s token has been read.
    pub(super) const fn remote_static(&self) -> Option<&PublicKey> {
        self.remote_static.as_ref()
    }

    /// The transcript hash.
    #[cfg(test)]
    pub(super) const fn handshake_hash(&self) -> &[u8; DH_LEN] {
        self.symmetric.handshake_hash()
    }

    /// Message 1, initiator: "e", then the payload in the clear.
    pub(super) fn write_message1(
        &mut self,
        ephemeral: SecretKey,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SecureError> {
        // e: the ephemeral key in the clear, folded into the transcript.
        self.write_ephemeral(ephemeral, out);
        // No key yet, so the payload is hashed and sent as is.
        self.symmetric.encrypt_and_hash(payload, out)
    }

    /// Message 1, responder side.
    pub(super) fn read_message1(&mut self, message: &[u8]) -> Result<Vec<u8>, SecureError> {
        // e: the initiator's ephemeral key.
        let payload = self.read_ephemeral(message)?;
        // The payload is plaintext; it still enters the transcript.
        self.symmetric.decrypt_and_hash(payload)
    }

    /// Message 2, responder: "e, ee, s, es", then the encrypted payload.
    pub(super) fn write_message2(
        &mut self,
        ephemeral: SecretKey,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SecureError> {
        let remote_ephemeral = self.remote_ephemeral.ok_or(SecureError::InvalidKey)?;
        // The ee secret is computed first, but mixed only after e enters the transcript.
        let ee = Self::dh(&ephemeral, &remote_ephemeral)?;
        // e: the responder's ephemeral key, in the clear.
        self.write_ephemeral(ephemeral, out);
        // ee: both ephemerals; from here on every field is encrypted.
        self.symmetric.mix_key(ee.as_bytes());
        // s: the static key, encrypted: 32 + 16 tag bytes.
        let static_public = self.static_secret.public_key();
        self.symmetric
            .encrypt_and_hash(static_public.as_bytes(), out)?;
        // es: initiator ephemeral with responder static.
        let static_secret = self.static_secret.clone();
        self.mix_dh(&static_secret, &remote_ephemeral)?;
        self.symmetric.encrypt_and_hash(payload, out)
    }

    /// Message 2, initiator side.
    pub(super) fn read_message2(&mut self, message: &[u8]) -> Result<Vec<u8>, SecureError> {
        let ephemeral = self.ephemeral.clone().ok_or(SecureError::InvalidKey)?;
        // e: the responder's ephemeral key.
        let rest = self.read_ephemeral(message)?;
        let remote_ephemeral = self.remote_ephemeral.ok_or(SecureError::InvalidKey)?;
        // ee.
        self.mix_dh(&ephemeral, &remote_ephemeral)?;
        // s: the responder's encrypted static key.
        let rest = self.read_static(rest)?;
        // es: our ephemeral with their static.
        let remote_static = self.remote_static.ok_or(SecureError::InvalidKey)?;
        self.mix_dh(&ephemeral, &remote_static)?;
        self.symmetric.decrypt_and_hash(rest)
    }

    /// Message 3, initiator: "s, se", then the encrypted payload.
    pub(super) fn write_message3(
        &mut self,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SecureError> {
        let remote_ephemeral = self.remote_ephemeral.ok_or(SecureError::InvalidKey)?;
        // s: our static key, encrypted.
        let static_public = self.static_secret.public_key();
        self.symmetric
            .encrypt_and_hash(static_public.as_bytes(), out)?;
        // se: our static with their ephemeral.
        let static_secret = self.static_secret.clone();
        self.mix_dh(&static_secret, &remote_ephemeral)?;
        self.symmetric.encrypt_and_hash(payload, out)
    }

    /// Message 3, responder side.
    pub(super) fn read_message3(&mut self, message: &[u8]) -> Result<Vec<u8>, SecureError> {
        let ephemeral = self.ephemeral.clone().ok_or(SecureError::InvalidKey)?;
        // s: the initiator's encrypted static key.
        let rest = self.read_static(message)?;
        // se: our ephemeral with their static.
        let remote_static = self.remote_static.ok_or(SecureError::InvalidKey)?;
        self.mix_dh(&ephemeral, &remote_static)?;
        self.symmetric.decrypt_and_hash(rest)
    }

    /// The transport ciphers, as this side sends and receives.
    pub(super) fn split(&self) -> (CipherState, CipherState) {
        let (initiator_to_responder, responder_to_initiator) = self.symmetric.split();
        // Each side sends with one key and receives with the other.
        match self.role {
            Role::Initiator => (initiator_to_responder, responder_to_initiator),
            Role::Responder => (responder_to_initiator, initiator_to_responder),
        }
    }

    /// Sends an e token and keeps the secret.
    fn write_ephemeral(&mut self, ephemeral: SecretKey, out: &mut Vec<u8>) {
        let public = ephemeral.public_key();
        out.extend_from_slice(public.as_bytes());
        self.symmetric.mix_hash(public.as_bytes());
        self.ephemeral = Some(ephemeral);
    }

    /// Reads an e token, returning the rest of the message.
    fn read_ephemeral<'a>(&mut self, message: &'a [u8]) -> Result<&'a [u8], SecureError> {
        let (key, rest) =
            message
                .split_first_chunk::<DH_LEN>()
                .ok_or(SecureError::MessageTooShort {
                    needed: DH_LEN,
                    len: message.len(),
                })?;
        self.symmetric.mix_hash(key);
        self.remote_ephemeral = Some(PublicKey::from_bytes(*key));
        Ok(rest)
    }

    /// Reads an encrypted s token, returning the rest of the message.
    fn read_static<'a>(&mut self, message: &'a [u8]) -> Result<&'a [u8], SecureError> {
        // The key carries a tag once a key is mixed in, which XX guarantees here.
        let sealed_len = self.symmetric.sealed_len(DH_LEN);
        if message.len() < sealed_len {
            return Err(SecureError::MessageTooShort {
                needed: sealed_len,
                len: message.len(),
            });
        }
        let (sealed, rest) = message.split_at(sealed_len);
        let key: [u8; DH_LEN] = self
            .symmetric
            .decrypt_and_hash(sealed)?
            .try_into()
            .map_err(|_| SecureError::InvalidKey)?;
        self.remote_static = Some(PublicKey::from_bytes(key));
        Ok(rest)
    }

    /// Folds the DH of a local secret and a remote key into the chaining key.
    fn mix_dh(&mut self, secret: &SecretKey, public: &PublicKey) -> Result<(), SecureError> {
        let shared = Self::dh(secret, public)?;
        self.symmetric.mix_key(shared.as_bytes());
        Ok(())
    }

    /// The X25519 shared secret of a local secret and a remote key.
    fn dh(secret: &SecretKey, public: &PublicKey) -> Result<SharedSecret, SecureError> {
        // A low-order remote point yields zero, which Noise lets us refuse.
        secret
            .diffie_hellman(public)
            .map_err(|_| SecureError::InvalidKey)
    }
}
