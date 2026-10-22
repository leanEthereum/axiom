//! `/plaintext/2.0.0`: an identity exchange with no protection at all.
//!
//! # Overview
//!
//! Each side sends its identifier and public key once, then bytes flow unchanged.
//! Nothing is proven: a peer may claim any key it likes.
//! It exists for tests only; real connections use Noise.
//!
//! ```text
//! message Exchange {
//!   optional bytes id = 1;          binary multihash
//!   optional PublicKey pubkey = 2;
//! }
//!
//! wire: [ varint length ][ Exchange ]   once per direction, then raw data
//! ```
//!
//! See `libp2p/specs/plaintext/README.md`.

use std::mem;

use super::{Handshake, Open, Role, Seal, SecureError, SecureSession, SecurityUpgrade};
use crate::{
    identity::{PeerId, PublicKey},
    protobuf::{FieldReader, FieldWriter, LengthPrefixedDecoder, ProtoMessage, ProtobufError},
};

/// The multistream-select name.
pub const PROTOCOL: &str = "/plaintext/2.0.0";

/// Longest exchange message accepted; an RSA key is the largest legitimate content.
const MAX_EXCHANGE_LEN: usize = 4096;

/// The identity announcement both sides send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchange {
    /// The sender's identifier.
    pub id: PeerId,
    /// The sender's public key.
    pub pubkey: PublicKey,
}

impl ProtoMessage for Exchange {
    fn encode_to(&self, out: &mut Vec<u8>) {
        let mut fields = FieldWriter::new(out);
        fields.bytes(1, self.id.as_bytes());
        fields.message(2, &self.pubkey);
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        let mut id = None;
        let mut pubkey = None;
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match field.number {
                1 => id = Some(field.bytes()?),
                2 => pubkey = Some(PublicKey::decode(field.bytes()?)?),
                _ => {}
            }
        }
        // The schema marks both optional, but the protocol is meaningless without them.
        let id = id.ok_or(ProtobufError::MissingField(1))?;
        let id = PeerId::from_bytes(id).map_err(|_| ProtobufError::InvalidValue {
            field: 1,
            expected: "peer id",
        })?;
        Ok(Self {
            id,
            pubkey: pubkey.ok_or(ProtobufError::MissingField(2))?,
        })
    }
}

/// The plaintext security protocol for one local identity.
#[derive(Clone, Debug)]
pub struct PlaintextConfig {
    /// The key this node announces.
    local_key: PublicKey,
}

impl PlaintextConfig {
    /// A configuration announcing a key.
    #[must_use]
    pub const fn new(local_key: PublicKey) -> Self {
        Self { local_key }
    }
}

impl SecurityUpgrade for PlaintextConfig {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn handshake(&self, _role: Role, expected: Option<PeerId>) -> Box<dyn Handshake> {
        // Both roles behave the same: send the exchange at once, then read the peer's.
        let exchange = Exchange {
            id: PeerId::from_public_key(&self.local_key),
            pubkey: self.local_key.clone(),
        };
        let mut outbound = Vec::new();
        exchange.encode_length_prefixed(&mut outbound);
        Box::new(PlaintextHandshake {
            expected,
            outbound,
            inbound: LengthPrefixedDecoder::new(MAX_EXCHANGE_LEN),
        })
    }
}

/// A plaintext exchange in progress.
#[derive(Debug)]
struct PlaintextHandshake {
    /// The peer the dialer meant to reach.
    expected: Option<PeerId>,
    /// Bytes waiting to be written.
    outbound: Vec<u8>,
    /// Splits the peer's exchange off the bytes received.
    inbound: LengthPrefixedDecoder,
}

impl Handshake for PlaintextHandshake {
    fn take_output(&mut self) -> Vec<u8> {
        mem::take(&mut self.outbound)
    }

    fn receive(&mut self, bytes: &[u8]) -> Result<Option<SecureSession>, SecureError> {
        self.inbound.feed(bytes);
        let Some(body) = self.inbound.next_frame()? else {
            return Ok(None);
        };
        let exchange = Exchange::decode(body)?;
        // The identifier must be derived from the announced key.
        let derived = PeerId::from_public_key(&exchange.pubkey);
        if exchange.id != derived {
            return Err(SecureError::IdentifierMismatch {
                claimed: exchange.id,
                derived,
            });
        }
        // The dialer also checks it reached the peer it asked for.
        if let Some(expected) = self.expected.take()
            && expected != exchange.id
        {
            return Err(SecureError::UnexpectedPeer {
                expected,
                actual: exchange.id,
            });
        }
        // Bytes after the exchange are already application data.
        let early_plaintext = self.inbound.take_remainder();
        Ok(Some(SecureSession {
            remote_peer: exchange.id,
            remote_key: exchange.pubkey,
            sealer: Box::new(Passthrough),
            opener: Box::new(Passthrough),
            early_plaintext,
        }))
    }
}

/// The identity cipher: bytes pass unchanged.
#[derive(Clone, Copy, Debug)]
struct Passthrough;

impl Seal for Passthrough {
    fn seal(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), SecureError> {
        out.extend_from_slice(plaintext);
        Ok(())
    }
}

impl Open for Passthrough {
    fn open(&mut self, wire: &[u8], out: &mut Vec<u8>) -> Result<(), SecureError> {
        out.extend_from_slice(wire);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn exchange_and_pass_data() {
        let alice = PlaintextConfig::new(PublicKey::secp256k1([2; 33]));
        let bob_key = PublicKey::secp256k1([3; 33]);
        let bob = PlaintextConfig::new(bob_key.clone());
        let bob_id = PeerId::from_public_key(&bob_key);

        // The dialer expects bob; bob expects nobody in particular.
        let mut dialer = alice.handshake(Role::Initiator, Some(bob_id.clone()));
        let mut listener = bob.handshake(Role::Responder, None);

        // Each first flight is one exchange: 1-byte prefix, 41-byte id field, 39-byte key field.
        //
        //     id field   = 0x0a 0x27 <39-byte multihash>      = 41 bytes
        //     key field  = 0x12 0x25 <37-byte PublicKey>      = 39 bytes
        //     prefix     = 80 = 0x50
        let to_bob = dialer.take_output();
        assert_eq!(to_bob.len(), 1 + 80);
        assert_eq!(to_bob[0], 80);

        // Bob receives the exchange plus three early data bytes.
        let mut flight = to_bob;
        flight.extend_from_slice(b"abc");
        let session = listener.receive(&flight).unwrap().unwrap();
        assert_eq!(
            session.remote_peer,
            PeerId::from_public_key(&PublicKey::secp256k1([2; 33]))
        );
        assert_eq!(session.early_plaintext, b"abc");

        // Alice completes with bob's exchange.
        let mut session = dialer.receive(&listener.take_output()).unwrap().unwrap();
        assert_eq!(session.remote_peer, bob_id);
        let mut out = Vec::new();
        session.sealer.seal(b"xyz", &mut out).unwrap();
        assert_eq!(out, b"xyz");
    }

    #[test]
    fn dialer_rejects_the_wrong_peer() {
        let carol = PeerId::from_public_key(&PublicKey::secp256k1([9; 33]));
        let mut dialer = PlaintextConfig::new(PublicKey::secp256k1([2; 33]))
            .handshake(Role::Initiator, Some(carol.clone()));
        let mut bob =
            PlaintextConfig::new(PublicKey::secp256k1([3; 33])).handshake(Role::Responder, None);
        let error = dialer.receive(&bob.take_output()).unwrap_err();
        assert_eq!(
            error,
            SecureError::UnexpectedPeer {
                expected: carol,
                actual: PeerId::from_public_key(&PublicKey::secp256k1([3; 33]))
            }
        );
    }

    #[test]
    fn rejects_identifier_of_another_key() {
        // Mutation: claim key 3 under the identifier of key 4.
        let exchange = Exchange {
            id: PeerId::from_public_key(&PublicKey::secp256k1([4; 33])),
            pubkey: PublicKey::secp256k1([3; 33]),
        };
        let mut wire = Vec::new();
        exchange.encode_length_prefixed(&mut wire);
        let mut listener =
            PlaintextConfig::new(PublicKey::secp256k1([2; 33])).handshake(Role::Responder, None);
        assert_eq!(
            listener.receive(&wire).unwrap_err(),
            SecureError::IdentifierMismatch {
                claimed: PeerId::from_public_key(&PublicKey::secp256k1([4; 33])),
                derived: PeerId::from_public_key(&PublicKey::secp256k1([3; 33])),
            }
        );
    }

    #[test]
    fn an_identifier_that_is_not_a_peer_id_is_named_as_such() {
        // Mutation: field 1 holds two bytes that are no multihash, beside a valid key.
        //
        //     field 1 = 0xff 0xff     (truncated varint, not a peer id)
        //     field 2 = a secp256k1 public key
        let mut bytes = Vec::new();
        let mut fields = FieldWriter::new(&mut bytes);
        fields.bytes(1, &[0xff, 0xff]);
        fields.message(2, &PublicKey::secp256k1([3; 33]));

        // The error points at the field and what it should hold, not at a missing field.
        assert_eq!(
            Exchange::decode(&bytes),
            Err(ProtobufError::InvalidValue {
                field: 1,
                expected: "peer id",
            })
        );
    }

    proptest! {
        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
            let mut listener = PlaintextConfig::new(PublicKey::secp256k1([2; 33])).handshake(Role::Responder, None);
            let _ = listener.receive(&bytes);
            let _ = Exchange::decode(&bytes);
        }
    }
}
