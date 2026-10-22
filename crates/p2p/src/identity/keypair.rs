//! The local secp256k1 identity: the secret that signs and the key peers see.

use std::fmt;

use axiom_crypto::secp256k1::{Secp256k1Error, SecretKey};
use sha2::{Digest, Sha256};

use super::{DerSignature, PeerId, PublicKey};

/// A secp256k1 identity key pair, the identity Ethereum consensus nodes use.
///
/// The secret clears its bytes when dropped.
/// The node persists the 32 secret bytes and reloads them at start.
#[derive(Clone)]
pub struct Keypair {
    /// The signing scalar.
    secret: SecretKey,
    /// The public key in the libp2p envelope.
    public: PublicKey,
}

impl Keypair {
    /// Loads a key pair from its 32-byte big-endian secret.
    ///
    /// # Errors
    ///
    /// Fails when the value is zero or not below the group order.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, Secp256k1Error> {
        let secret = SecretKey::from_bytes(bytes)?;
        let public = PublicKey::secp256k1(secret.public_key().to_compressed());
        Ok(Self { secret, public })
    }

    /// The 32-byte secret, the form the node persists.
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// The public key, as handshakes and identify announce it.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The peer identifier derived from the public key.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_public_key(&self.public)
    }

    /// Signs a message the libp2p way: ECDSA over its SHA-256 hash, DER-encoded.
    ///
    /// The signature is deterministic and low-s.
    /// See `libp2p/specs/peer-ids/peer-ids.md`, section on secp256k1.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> DerSignature {
        let hash: [u8; 32] = Sha256::digest(message).into();
        DerSignature::from_signature(&self.secret.sign(&hash))
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only the public half is printable.
        f.debug_struct("Keypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{identity::KeyType, protobuf::ProtoMessage, testing::hex};

    /// The secp256k1 private key of the peer-ids spec test vectors.
    const SPEC_SECRET: &str = "53dadf1d5a164d6b4acdb15e24aa4c5b1d3461bdbd42abedb0a4404d56ced8fb";

    /// The spec secret as a key pair.
    fn spec_keypair() -> Keypair {
        let secret: [u8; 32] = hex(SPEC_SECRET).try_into().unwrap();
        Keypair::from_secret_bytes(&secret).unwrap()
    }

    #[test]
    fn spec_secret_gives_the_spec_public_key() {
        // The peer-ids spec pairs this secret with the envelope 08 02 12 21 03 7777e9...
        let keypair = spec_keypair();
        assert_eq!(keypair.public_key().key_type, KeyType::Secp256k1);
        assert_eq!(
            keypair.public_key().encode(),
            hex("08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99")
        );
        // Secp256k1 peer identifiers render with the 16Uiu2 prefix.
        assert!(keypair.peer_id().to_string().starts_with("16Uiu2"));
        assert_eq!(keypair.secret_bytes().to_vec(), hex(SPEC_SECRET));
    }

    #[test]
    fn zero_secret_is_refused() {
        assert_eq!(
            Keypair::from_secret_bytes(&[0; 32]).unwrap_err(),
            Secp256k1Error::InvalidSecretKey
        );
    }

    #[test]
    fn signature_verifies_and_binds_the_message() {
        // Sign the static-key binding over the 32 bytes 00 01 .. 1f.
        let keypair = spec_keypair();
        let mut message = b"noise-libp2p-static-key:".to_vec();
        message.extend(0u8..32);
        let signature = keypair.sign(&message);

        // RFC 6979 makes it deterministic; Python cryptography 46.0.5 verifies these exact bytes.
        // Here s = 03f7..., so its INTEGER needs no sign byte: 0x44 body bytes.
        assert_eq!(
            signature.as_bytes(),
            hex(concat!(
                "3044022048cada804322ba9b1761fddd10e9e1fadc29fdf618752789ab2007dcb83d4dd1",
                "022003f746076040e24e49fb9f241addfb95215ac46d9fecc01d0daea5277532345d"
            ))
        );
        assert!(keypair.public_key().verify(&message, signature.as_bytes()));

        // Mutation: the last static key byte changes from 0x1f to 0x20.
        let mut other = message.clone();
        other[55] = 0x20;
        assert!(!keypair.public_key().verify(&other, signature.as_bytes()));
    }
}
