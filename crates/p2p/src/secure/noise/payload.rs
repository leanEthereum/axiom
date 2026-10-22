//! The protobuf payload each side sends inside its encrypted handshake message.

use crate::{
    identity::PublicKey,
    protobuf::{FieldReader, FieldWriter, ProtoMessage, ProtobufError},
};

/// Optional capabilities announced during the handshake.
///
/// ```text
/// message NoiseExtensions {
///     repeated bytes webtransport_certhashes = 1;
///     repeated string stream_muxers = 2;
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoiseExtensions {
    /// Certificate hashes for WebTransport, unused over TCP.
    pub webtransport_certhashes: Vec<Vec<u8>>,
    /// Multiplexers the sender supports, letting peers skip a negotiation round.
    pub stream_muxers: Vec<String>,
}

impl ProtoMessage for NoiseExtensions {
    fn encode_to(&self, out: &mut Vec<u8>) {
        let mut fields = FieldWriter::new(out);
        for hash in &self.webtransport_certhashes {
            fields.bytes(1, hash);
        }
        for muxer in &self.stream_muxers {
            fields.bytes(2, muxer.as_bytes());
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        let mut extensions = Self::default();
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match field.number {
                1 => extensions
                    .webtransport_certhashes
                    .push(field.bytes()?.to_vec()),
                2 => extensions.stream_muxers.push(field.string()?.to_owned()),
                _ => {}
            }
        }
        Ok(extensions)
    }
}

/// The identity proof carried in handshake messages 2 and 3.
///
/// ```text
/// message NoiseHandshakePayload {
///   optional bytes identity_key = 1;          serialized PublicKey
///   optional bytes identity_sig = 2;          signature over the static key
///   optional NoiseExtensions extensions = 4;
/// }
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoiseHandshakePayload {
    /// The sender's libp2p identity key.
    pub identity_key: Option<PublicKey>,
    /// The identity key's signature over the sender's static DH key.
    pub identity_sig: Option<Vec<u8>>,
    /// Optional capabilities.
    pub extensions: Option<NoiseExtensions>,
}

impl ProtoMessage for NoiseHandshakePayload {
    fn encode_to(&self, out: &mut Vec<u8>) {
        let mut fields = FieldWriter::new(out);
        if let Some(key) = &self.identity_key {
            fields.message(1, key);
        }
        if let Some(signature) = &self.identity_sig {
            fields.bytes(2, signature);
        }
        if let Some(extensions) = &self.extensions {
            fields.message(4, extensions);
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        let mut payload = Self::default();
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match field.number {
                1 => payload.identity_key = Some(PublicKey::decode(field.bytes()?)?),
                2 => payload.identity_sig = Some(field.bytes()?.to_vec()),
                4 => payload.extensions = Some(NoiseExtensions::decode(field.bytes()?)?),
                _ => {}
            }
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn layout() {
        // A payload with a secp256k1 key, a 2-byte signature, and one muxer.
        let payload = NoiseHandshakePayload {
            identity_key: Some(PublicKey::secp256k1([2; 33])),
            identity_sig: Some(vec![0xaa, 0xbb]),
            extensions: Some(NoiseExtensions {
                webtransport_certhashes: vec![],
                stream_muxers: vec!["/yamux/1.0.0".into()],
            }),
        };
        let bytes = payload.encode();
        // Field 1 (key 0x0a) wraps the 37-byte PublicKey envelope.
        assert_eq!(&bytes[..2], &[0x0a, 37]);
        // Field 2 (key 0x12) follows: 2 + 37 bytes in.
        assert_eq!(&bytes[39..43], &[0x12, 2, 0xaa, 0xbb]);
        // Field 4 (key 0x22) wraps the extensions message: [0x12, 12, "/yamux/1.0.0"].
        assert_eq!(&bytes[43..46], &[0x22, 14, 0x12]);
        assert_eq!(NoiseHandshakePayload::decode(&bytes), Ok(payload));
    }

    proptest! {
        #[test]
        fn round_trip(sig in proptest::collection::vec(any::<u8>(), 0..80), muxers in proptest::collection::vec("[a-z/.0-9]{0,12}", 0..3)) {
            let payload = NoiseHandshakePayload {
                identity_key: Some(PublicKey::secp256k1([3; 33])),
                identity_sig: Some(sig),
                extensions: Some(NoiseExtensions { webtransport_certhashes: vec![vec![1, 2]], stream_muxers: muxers }),
            };
            prop_assert_eq!(NoiseHandshakePayload::decode(&payload.encode()), Ok(payload));
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
            let _ = NoiseHandshakePayload::decode(&bytes);
        }
    }
}
