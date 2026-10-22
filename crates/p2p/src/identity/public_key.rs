//! Public keys in the libp2p protobuf envelope.

use crate::protobuf::{
    FieldReader, ProtoMessage, ProtobufError, encode_bytes_field, encode_varint_field,
};

/// The signature scheme a public key belongs to.
///
/// Ethereum consensus nodes use secp256k1 identities.
/// The other schemes appear here so that the envelope decodes any libp2p key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyType {
    /// RSA, with a DER-encoded PKIX key.
    Rsa,
    /// Ed25519, with a 32-byte key.
    Ed25519,
    /// Secp256k1, with a 33-byte compressed point.
    Secp256k1,
    /// ECDSA over P-256, with a DER-encoded PKIX key.
    Ecdsa,
}

impl KeyType {
    /// Value of this scheme in the protobuf enum.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Rsa => 0,
            Self::Ed25519 => 1,
            Self::Secp256k1 => 2,
            Self::Ecdsa => 3,
        }
    }

    /// The scheme a protobuf enum value names, if any.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Rsa),
            1 => Some(Self::Ed25519),
            2 => Some(Self::Secp256k1),
            3 => Some(Self::Ecdsa),
            _ => None,
        }
    }
}

/// A public key as libp2p serializes it.
///
/// ```text
/// message PublicKey {
///   required KeyType Type = 1;
///   required bytes Data = 2;
/// }
///
/// secp256k1 example (peer-ids spec test vector):
///   08 02                 field 1, varint 2 (secp256k1)
///   12 21                 field 2, 33 bytes
///   03 7777e9...bfca99    compressed point
/// ```
///
/// The key bytes are not checked to be a valid point here.
/// The signature scheme rejects them when it verifies a signature.
///
/// Encoders must emit the fields in order, since peer identifiers hash this encoding.
/// See `libp2p/specs/peer-ids/peer-ids.md`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey {
    /// Signature scheme of the key.
    pub key_type: KeyType,
    /// Scheme-specific key bytes.
    pub data: Vec<u8>,
}

impl PublicKey {
    /// A secp256k1 key from its 33-byte compressed encoding.
    #[must_use]
    pub fn secp256k1(compressed: [u8; 33]) -> Self {
        Self {
            key_type: KeyType::Secp256k1,
            data: compressed.to_vec(),
        }
    }
}

impl ProtoMessage for PublicKey {
    fn encode_to(&self, out: &mut Vec<u8>) {
        // Deterministic order: type first, data second.
        encode_varint_field(1, self.key_type.code(), out);
        encode_bytes_field(2, &self.data, out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        let mut key_type = None;
        let mut data = None;
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match field.number {
                // The scheme must be one of the four the schema lists.
                1 => {
                    let code = field.varint()?;
                    let parsed = KeyType::from_code(code).ok_or(ProtobufError::InvalidEnum {
                        field: 1,
                        value: code,
                    })?;
                    key_type = Some(parsed);
                }
                2 => data = Some(field.bytes()?.to_vec()),
                // Unknown fields are skipped for forward compatibility.
                _ => {}
            }
        }
        // Both fields are required in the proto2 schema.
        Ok(Self {
            key_type: key_type.ok_or(ProtobufError::MissingField(1))?,
            data: data.ok_or(ProtobufError::MissingField(2))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::testing::hex;

    #[test]
    fn spec_vectors_round_trip() {
        // Public keys from the peer-ids spec test vector table.
        let secp =
            hex("08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99");
        let ed = hex("080112201ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e");

        // The secp256k1 envelope wraps a 33-byte point starting 0x03.
        let key = PublicKey::decode(&secp).unwrap();
        assert_eq!(key.key_type, KeyType::Secp256k1);
        assert_eq!(key.data.len(), 33);
        assert_eq!(key.data[0], 0x03);
        assert_eq!(key.encode(), secp);

        // The ed25519 envelope wraps a 32-byte key.
        let key = PublicKey::decode(&ed).unwrap();
        assert_eq!(key.key_type, KeyType::Ed25519);
        assert_eq!(key.data.len(), 32);
        assert_eq!(key.encode(), ed);
    }

    #[test]
    fn rejects_missing_and_unknown() {
        // Only the type field: data is required.
        assert_eq!(
            PublicKey::decode(&[0x08, 0x02]),
            Err(ProtobufError::MissingField(2))
        );
        // Type 9 is not in the enum.
        assert_eq!(
            PublicKey::decode(&[0x08, 0x09, 0x12, 0x00]),
            Err(ProtobufError::InvalidEnum { field: 1, value: 9 })
        );
    }

    proptest! {
        #[test]
        fn round_trip(code in 0u64..4, data in proptest::collection::vec(any::<u8>(), 0..64)) {
            let key = PublicKey { key_type: KeyType::from_code(code).unwrap(), data };
            prop_assert_eq!(PublicKey::decode(&key.encode()), Ok(key));
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = PublicKey::decode(&bytes);
        }
    }
}
