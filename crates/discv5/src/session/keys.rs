//! Session key agreement and the identity proof of the handshake.
//!
//! See discv5-theory.md, "Handshake Steps", step 3, and "Identity-Specific Cryptography".

use std::fmt;

use axiom_crypto::{
    hkdf::Hkdf,
    secp256k1::{PublicKey, SecretKey, Signature},
};
use sha2::{Digest, Sha256};

use crate::node_id::NodeId;

/// Context string of the key derivation.
const KDF_INFO: &[u8] = b"discovery v5 key agreement";

/// Context string of the identity proof.
const ID_SIGNATURE_TEXT: &[u8] = b"discovery v5 identity proof";

/// The unmasked WHOAREYOU packet: masking IV, static header, and authdata.
///
/// Both sides bind the session to it, as HKDF salt and inside the identity proof.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChallengeData(pub Vec<u8>);

/// The two AES-128-GCM keys of a session, one per direction.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Seals messages from the handshake initiator.
    pub initiator_key: [u8; 16],
    /// Seals messages from the challenger.
    pub recipient_key: [u8; 16],
}

impl SessionKeys {
    /// Derives the keys from an ECDH secret and the challenge.
    ///
    /// # Algorithm
    ///
    /// ```text
    /// secret   = compressed ECDH point, 33 bytes
    /// prk      = HKDF-Extract(salt = challenge-data, ikm = secret)
    /// key-data = HKDF-Expand(prk, "discovery v5 key agreement" || id-A || id-B, 32)
    /// initiator-key = key-data[..16],  recipient-key = key-data[16..]
    /// ```
    #[must_use]
    pub fn derive(
        secret: &[u8; 33],
        challenge: &ChallengeData,
        initiator: &NodeId,
        recipient: &NodeId,
    ) -> Self {
        // The info string binds both identities, initiator first.
        let mut info = Vec::with_capacity(KDF_INFO.len() + 64);
        info.extend_from_slice(KDF_INFO);
        info.extend_from_slice(&initiator.0);
        info.extend_from_slice(&recipient.0);
        let mut key_data = [0_u8; 32];
        // Invariant: 32 bytes is far below the HKDF output limit of 8160.
        Hkdf::extract(&challenge.0, secret)
            .expand(&info, &mut key_data)
            .expect("32 bytes is within the HKDF limit");
        let mut keys = Self {
            initiator_key: [0; 16],
            recipient_key: [0; 16],
        };
        keys.initiator_key.copy_from_slice(&key_data[..16]);
        keys.recipient_key.copy_from_slice(&key_data[16..]);
        keys
    }

    /// The initiator's derivation: ephemeral secret with the challenger's static key.
    #[must_use]
    pub fn initiate(
        ephemeral: &SecretKey,
        remote: &PublicKey,
        challenge: &ChallengeData,
        local_id: &NodeId,
        remote_id: &NodeId,
    ) -> Self {
        // The shared point in compressed form is the input keying material.
        let secret = ephemeral.diffie_hellman(remote).to_compressed();
        Self::derive(&secret, challenge, local_id, remote_id)
    }

    /// The challenger's derivation: static secret with the initiator's ephemeral key.
    #[must_use]
    pub fn accept(
        local: &SecretKey,
        ephemeral: &PublicKey,
        challenge: &ChallengeData,
        remote_id: &NodeId,
        local_id: &NodeId,
    ) -> Self {
        // ECDH is symmetric, so both sides reach the same point.
        let secret = local.diffie_hellman(ephemeral).to_compressed();
        Self::derive(&secret, challenge, remote_id, local_id)
    }
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keys are secret: never print them.
        f.debug_struct("SessionKeys").finish_non_exhaustive()
    }
}

/// The handshake's proof that the initiator holds its record's key.
///
/// ```text
/// input     = "discovery v5 identity proof" || challenge-data || ephemeral-pubkey || id-B
/// signature = sign(sha256(input)), 64 bytes r || s
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdSignature(pub [u8; 64]);

impl IdSignature {
    /// Signs the challenge, the ephemeral key, and the challenger's id.
    #[must_use]
    pub fn sign(
        key: &SecretKey,
        challenge: &ChallengeData,
        ephemeral: &PublicKey,
        challenger: &NodeId,
    ) -> Self {
        // RFC 6979 makes the signature a function of its inputs.
        Self(
            key.sign(&Self::hash(challenge, ephemeral, challenger))
                .to_bytes(),
        )
    }

    /// Whether the signature verifies under the initiator's static key.
    #[must_use]
    pub fn verify(
        &self,
        key: &PublicKey,
        challenge: &ChallengeData,
        ephemeral: &PublicKey,
        challenger: &NodeId,
    ) -> bool {
        // Malformed components and high-s forms fail like a wrong signature.
        Signature::from_bytes(&self.0).is_ok_and(|signature| {
            key.verify(&Self::hash(challenge, ephemeral, challenger), &signature)
                .is_ok()
        })
    }

    /// The SHA-256 digest of the signed input.
    fn hash(challenge: &ChallengeData, ephemeral: &PublicKey, challenger: &NodeId) -> [u8; 32] {
        // The fields in spec order.
        let mut hasher = Sha256::new();
        hasher.update(ID_SIGNATURE_TEXT);
        hasher.update(&challenge.0);
        hasher.update(ephemeral.to_compressed());
        hasher.update(challenger.0);
        hasher.finalize().into()
    }
}
