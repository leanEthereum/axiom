//! Peer identifiers: multihashes of encoded public keys.

use std::{fmt, str::FromStr};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    identity::PublicKey,
    multibase::Multibase,
    protobuf::{ProtoMessage, ProtobufError},
    varint::{Varint, VarintError},
};

/// Multihash code of the identity function, which stores its input verbatim.
const IDENTITY_CODE: u64 = 0x00;

/// Multihash code of SHA-256.
const SHA256_CODE: u64 = 0x12;

/// Longest encoded key stored verbatim rather than hashed.
///
/// The peer-ids spec fixes 42 bytes.
/// A protobuf secp256k1 key takes 37, so Ethereum identifiers always embed the key.
const MAX_INLINE_KEY_LEN: usize = 42;

/// Multicodec of a libp2p key inside a CIDv1.
const LIBP2P_KEY_CODEC: u64 = 0x72;

/// The identifier of a libp2p node, derived from its public key.
///
/// ```text
/// encoded key <= 42 bytes:   [ 0x00 ][ varint len ][ encoded key ]     identity multihash
/// encoded key  > 42 bytes:   [ 0x12 ][ 0x20 ][ sha256(encoded key) ]   sha256 multihash
///
/// secp256k1: 37-byte envelope -> [0x00, 0x25, 08 02 12 21 <33 bytes>]
///            base58 text starts with "16Uiu2"
/// ```
///
/// See `libp2p/specs/peer-ids/peer-ids.md`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId {
    /// The multihash bytes, validated on construction.
    multihash: Vec<u8>,
}

impl PeerId {
    /// The identifier of a public key.
    #[must_use]
    pub fn from_public_key(key: &PublicKey) -> Self {
        let encoded = key.encode();
        let mut multihash = Vec::with_capacity(encoded.len() + 2);
        if encoded.len() <= MAX_INLINE_KEY_LEN {
            // Short keys are embedded: no hashing, only the multihash header.
            Varint::Multiformat.write(IDENTITY_CODE, &mut multihash);
            Varint::Multiformat.write(encoded.len() as u64, &mut multihash);
            multihash.extend_from_slice(&encoded);
        } else {
            // Long keys, such as RSA, are condensed to a SHA-256 digest.
            Varint::Multiformat.write(SHA256_CODE, &mut multihash);
            Varint::Multiformat.write(32, &mut multihash);
            multihash.extend_from_slice(&Sha256::digest(&encoded));
        }
        Self { multihash }
    }

    /// Parses a binary multihash.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PeerIdError> {
        let mut digest = bytes;
        // Phase 1: the hash function code.
        let code = Varint::Multiformat.read(&mut digest)?;
        // Phase 2: the digest length.
        let len = Varint::Multiformat.read(&mut digest)?;
        // Phase 3: the digest must fill the rest exactly.
        if digest.len() as u64 != len {
            return Err(PeerIdError::DigestLengthMismatch {
                declared: len,
                actual: digest.len(),
            });
        }
        match code {
            // An embedded key must itself be a valid envelope.
            IDENTITY_CODE if digest.len() <= MAX_INLINE_KEY_LEN => {
                PublicKey::decode(digest).map_err(PeerIdError::InvalidEmbeddedKey)?;
            }
            SHA256_CODE if digest.len() == 32 => {}
            _ => {
                return Err(PeerIdError::UnsupportedHash {
                    code,
                    len: digest.len(),
                });
            }
        }
        Ok(Self {
            multihash: bytes.to_vec(),
        })
    }

    /// The binary multihash.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.multihash
    }

    /// The public key embedded in an identity multihash, if this identifier embeds one.
    #[must_use]
    pub fn public_key(&self) -> Option<PublicKey> {
        // Embedded keys sit behind a two-byte header: code 0x00 and a one-byte length.
        //
        //     [0x00][len < 128][key bytes]
        match self.multihash.as_slice() {
            [0x00, _, key @ ..] => PublicKey::decode(key).ok(),
            _ => None,
        }
    }

    /// Whether this identifier belongs to a public key.
    #[must_use]
    pub fn matches(&self, key: &PublicKey) -> bool {
        *self == Self::from_public_key(key)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The legacy raw base58btc form, which the spec says to display.
        f.write_str(&Multibase::Base58Btc.encode(&self.multihash))
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for PeerId {
    type Err = PeerIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // Raw base58btc multihashes start with '1' (identity) or "Qm" (sha256).
        if text.starts_with('1') || text.starts_with("Qm") {
            let bytes = Multibase::Base58Btc
                .decode(text)
                .ok_or(PeerIdError::InvalidText)?;
            return Self::from_bytes(&bytes);
        }
        // A multibase 'b' prefix introduces a base32 CIDv1.
        //
        //     b <base32( [0x01 version][0x72 libp2p-key][multihash] )>
        if let Some(body) = text.strip_prefix('b') {
            let cid = Multibase::Base32Lower
                .decode(body)
                .ok_or(PeerIdError::InvalidText)?;
            let mut multihash = &cid[..];
            let version = Varint::Multiformat.read(&mut multihash)?;
            let codec = Varint::Multiformat.read(&mut multihash)?;
            if version != 1 || codec != LIBP2P_KEY_CODEC {
                return Err(PeerIdError::UnsupportedCid { version, codec });
            }
            return Self::from_bytes(multihash);
        }
        Err(PeerIdError::InvalidText)
    }
}

/// A byte string or text that is not a supported peer identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PeerIdError {
    /// A multihash or CID varint is malformed.
    #[error("malformed peer id varint: {0}")]
    Varint(#[from] VarintError),

    /// The multihash declares a digest length other than the bytes that follow.
    #[error("multihash declares {declared} digest bytes but holds {actual}")]
    DigestLengthMismatch {
        /// Digest length the multihash declares.
        declared: u64,
        /// Digest bytes present.
        actual: usize,
    },

    /// The key embedded in an identity multihash is not a valid key envelope.
    #[error("malformed embedded public key: {0}")]
    InvalidEmbeddedKey(#[source] ProtobufError),

    /// The multihash uses a function other than identity or SHA-256, or a digest length it forbids.
    #[error("unsupported multihash code {code:#x} with a {len}-byte digest")]
    UnsupportedHash {
        /// Multihash function code.
        code: u64,
        /// Digest length, in bytes.
        len: usize,
    },

    /// A base32 CID is not a version 1 CID of a libp2p key.
    #[error("unsupported CID version {version} with codec {codec:#x}")]
    UnsupportedCid {
        /// CID version.
        version: u64,
        /// Multicodec of the content.
        codec: u64,
    },

    /// The text is neither base58btc nor base32 with the expected prefix.
    ///
    /// The caller holds the text, so the error does not copy it.
    #[error("peer id text is neither base58btc nor a base32 CID")]
    InvalidText,
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{identity::KeyType, testing::hex};

    #[test]
    fn secp256k1_identifier_embeds_the_key() {
        // The peer-ids spec secp256k1 test vector: a 37-byte envelope.
        let envelope =
            hex("08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99");
        let key = PublicKey::decode(&envelope).unwrap();
        let id = PeerId::from_public_key(&key);

        // 37 <= 42 picks the identity multihash: [0x00, 0x25] then the envelope verbatim.
        assert_eq!(&id.as_bytes()[..2], &[0x00, 0x25]);
        assert_eq!(&id.as_bytes()[2..], &envelope[..]);
        assert_eq!(id.public_key(), Some(key.clone()));
        assert!(id.matches(&key));

        // Every secp256k1 identifier prints with the same "16Uiu2" prefix.
        let text = id.to_string();
        assert!(text.starts_with("16Uiu2"), "{text}");
        assert_eq!(text.parse::<PeerId>(), Ok(id));
    }

    #[test]
    fn ed25519_identifier_prints_12d3koo() {
        // The peer-ids spec ed25519 public key vector: 36 bytes, embedded.
        let envelope =
            hex("080112201ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e");
        let id = PeerId::from_public_key(&PublicKey::decode(&envelope).unwrap());
        assert!(id.to_string().starts_with("12D3KooW"));
    }

    #[test]
    fn long_key_is_hashed() {
        // A 64-byte RSA stand-in encodes to 67 bytes > 42, so it takes the SHA-256 multihash.
        let key = PublicKey {
            key_type: KeyType::Rsa,
            data: vec![7; 64],
        };
        let id = PeerId::from_public_key(&key);
        assert_eq!(&id.as_bytes()[..2], &[0x12, 0x20]);
        assert_eq!(&id.as_bytes()[2..], &Sha256::digest(key.encode())[..]);
        assert_eq!(id.public_key(), None);
        // Hashed identifiers print with the "Qm" prefix.
        assert!(id.to_string().starts_with("Qm"));
    }

    #[test]
    fn parses_the_spec_text_examples() {
        // Raw base58btc forms from the spec.
        let qm: PeerId = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
            .parse()
            .unwrap();
        assert_eq!(qm.as_bytes().len(), 34);
        let ed: PeerId = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"
            .parse()
            .unwrap();
        assert!(ed.public_key().is_some());
        // The CIDv1 form decodes to a SHA-256 multihash.
        let cid: PeerId = "bafzbeie5745rpv2m6tjyuugywy4d5ewrqgqqhfnf445he3omzpjbx5xqxe"
            .parse()
            .unwrap();
        assert_eq!(&cid.as_bytes()[..2], &[0x12, 0x20]);
    }

    #[test]
    fn rejects_bad_multihashes() {
        // Declared length 3, but 2 digest bytes follow.
        assert_eq!(
            PeerId::from_bytes(&[0x12, 0x03, 1, 2]),
            Err(PeerIdError::DigestLengthMismatch {
                declared: 3,
                actual: 2
            })
        );
        // A 31-byte SHA-256 digest is impossible.
        let mut short = vec![0x12, 31];
        short.extend_from_slice(&[0; 31]);
        assert_eq!(
            PeerId::from_bytes(&short),
            Err(PeerIdError::UnsupportedHash {
                code: 0x12,
                len: 31
            })
        );
        // Code 0x13 is SHA-512, not accepted for identifiers.
        assert_eq!(
            PeerId::from_bytes(&[0x13, 0x00]),
            Err(PeerIdError::UnsupportedHash { code: 0x13, len: 0 })
        );
        // A multihash cut inside its length varint.
        assert_eq!(
            PeerId::from_bytes(&[0x00, 0x80]),
            Err(PeerIdError::Varint(VarintError::Truncated { len: 1 }))
        );
        // An identity multihash of 2 bytes that are no key envelope: field 1 truncated.
        assert_eq!(
            PeerId::from_bytes(&[0x00, 0x02, 0x08, 0x80]),
            Err(PeerIdError::InvalidEmbeddedKey(ProtobufError::Truncated {
                needed: 2,
                remaining: 1
            }))
        );
        // A base32 CID of version 1 with the raw codec 0x55 instead of libp2p-key.
        assert_eq!(
            "bafkqaaa".parse::<PeerId>(),
            Err(PeerIdError::UnsupportedCid {
                version: 1,
                codec: 0x55
            })
        );
        // Text with neither prefix.
        assert_eq!("xyz".parse::<PeerId>(), Err(PeerIdError::InvalidText));
    }

    proptest! {
        #[test]
        fn text_round_trip(point in proptest::array::uniform32(any::<u8>()), parity in 2u8..4) {
            // A secp256k1-shaped key: parity byte then 32 coordinate bytes.
            let mut compressed = [0u8; 33];
            compressed[0] = parity;
            compressed[1..].copy_from_slice(&point);
            let id = PeerId::from_public_key(&PublicKey::secp256k1(compressed));
            prop_assert_eq!(id.to_string().parse::<PeerId>(), Ok(id.clone()));
            prop_assert_eq!(PeerId::from_bytes(id.as_bytes()), Ok(id));
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64), text in "\\PC{0,64}") {
            let _ = PeerId::from_bytes(&bytes);
            let _ = text.parse::<PeerId>();
        }
    }
}
