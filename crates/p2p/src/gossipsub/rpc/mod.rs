//! The gossipsub RPC envelope and its control messages, on the wire.
//!
//! # Overview
//!
//! Every frame on a gossipsub stream is one varint-length-prefixed RPC.
//!
//! ```text
//! message RPC {
//!   repeated SubOpts subscriptions = 1;   { optional bool subscribe = 1; optional string topic_id = 2; }
//!   repeated Message publish = 2;
//!   optional ControlMessage control = 3;
//! }
//! message Message {
//!   optional bytes from = 1;  optional bytes data = 2;  optional bytes seqno = 3;
//!   required string topic = 4;  optional bytes signature = 5;  optional bytes key = 6;
//! }
//! message ControlMessage {
//!   repeated ControlIHave ihave = 1;          { topic_id = 1; repeated bytes message_ids = 2; }
//!   repeated ControlIWant iwant = 2;          { repeated bytes message_ids = 1; }
//!   repeated ControlGraft graft = 3;          { topic_id = 1; }
//!   repeated ControlPrune prune = 4;          { topic_id = 1; repeated PeerInfo peers = 2; optional uint64 backoff = 3; }
//!   repeated ControlIDontWant idontwant = 5;  { repeated bytes message_ids = 1; }
//! }
//! message PeerInfo { optional bytes peer_id = 1; optional bytes signed_peer_record = 2; }
//! ```
//!
//! Message identifiers of any length other than 20 bytes are dropped while decoding.
//! The consensus p2p spec requires rejecting them.
//!
//! See `libp2p/specs/pubsub/README.md` and the gossipsub v1.0, v1.1, and v1.2 documents.

mod control;
mod message;

pub use control::{ControlMessage, Graft, IDontWant, IHave, IWant, PeerInfo, Prune};
pub use message::{RawMessage, SubOpts};

use crate::protobuf::{FieldReader, FieldWriter, ProtoMessage, ProtobufError};

/// The unit of exchange on a gossipsub stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rpc {
    /// Subscription changes.
    pub subscriptions: Vec<SubOpts>,
    /// Full messages.
    pub publish: Vec<RawMessage>,
    /// Mesh and gossip control.
    pub control: Option<ControlMessage>,
}

impl Rpc {
    /// Whether the RPC carries nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subscriptions.is_empty()
            && self.publish.is_empty()
            && self.control.as_ref().is_none_or(ControlMessage::is_empty)
    }
}

impl ProtoMessage for Rpc {
    fn encode_to(&self, out: &mut Vec<u8>) {
        let mut fields = FieldWriter::new(out);
        for subscription in &self.subscriptions {
            fields.message(1, subscription);
        }
        for message in &self.publish {
            fields.message(2, message);
        }
        if let Some(control) = &self.control
            && !control.is_empty()
        {
            fields.message(3, control);
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        let mut rpc = Self::default();
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match field.number {
                1 => rpc.subscriptions.push(SubOpts::decode(field.bytes()?)?),
                2 => rpc.publish.push(RawMessage::decode(field.bytes()?)?),
                3 => rpc.control = Some(ControlMessage::decode(field.bytes()?)?),
                _ => {}
            }
        }
        Ok(rpc)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{
        gossipsub::{MessageId, Topic},
        identity::{PeerId, PublicKey},
        protobuf::FieldWriter,
    };

    #[test]
    fn subscription_and_message_layout() {
        // One subscription to topic "t" and one anonymous message with data [0xaa].
        let rpc = Rpc {
            subscriptions: vec![SubOpts {
                subscribe: true,
                topic: Topic::new("t"),
            }],
            publish: vec![RawMessage::anonymous(Topic::new("t"), vec![0xaa])],
            control: None,
        };
        // RPC field 1 (0x0a), 5 bytes:  subscribe=1 [0x08 0x01], topic [0x12 0x01 't']
        // RPC field 2 (0x12), 6 bytes:  data [0x12 0x01 0xaa], topic [0x22 0x01 't']
        let expected = [
            0x0a, 0x05, 0x08, 0x01, 0x12, 0x01, b't', //
            0x12, 0x06, 0x12, 0x01, 0xaa, 0x22, 0x01, b't',
        ];
        assert_eq!(rpc.encode(), expected);
        assert_eq!(Rpc::decode(&expected), Ok(rpc));
    }

    #[test]
    fn control_layout() {
        // A GRAFT for "t": RPC field 3 → control field 3 → topic field 1.
        let rpc = Rpc {
            control: Some(ControlMessage {
                graft: vec![Graft {
                    topic: Topic::new("t"),
                }],
                ..ControlMessage::default()
            }),
            ..Rpc::default()
        };
        assert_eq!(rpc.encode(), [0x1a, 0x05, 0x1a, 0x03, 0x0a, 0x01, b't']);
    }

    #[test]
    fn drops_identifiers_that_are_not_20_bytes() {
        // An IWANT with one 20-byte and one 19-byte identifier.
        let mut iwant = Vec::new();
        let mut fields = FieldWriter::new(&mut iwant);
        fields.bytes(1, &[1; 20]);
        fields.bytes(1, &[2; 19]);
        let mut control = Vec::new();
        FieldWriter::new(&mut control).bytes(2, &iwant);
        let decoded = ControlMessage::decode(&control).unwrap();
        assert_eq!(
            decoded.iwant,
            [IWant {
                message_ids: vec![MessageId([1; 20])]
            }]
        );
    }

    #[test]
    fn strict_no_sign() {
        let mut message = RawMessage::anonymous(Topic::new("t"), vec![]);
        assert!(message.is_strict_no_sign());
        // Mutation: a sequence number is an authorship field.
        message.seqno = Some(vec![1]);
        assert!(!message.is_strict_no_sign());
    }

    /// Strategy over message identifiers.
    fn ids() -> impl Strategy<Value = Vec<MessageId>> {
        proptest::collection::vec(any::<[u8; 20]>().prop_map(MessageId), 0..4)
    }

    /// Strategy over topics.
    fn topic() -> impl Strategy<Value = Topic> {
        "[a-z0-9/_]{0,24}".prop_map(Topic::new)
    }

    /// Strategy over whole RPCs.
    fn rpc() -> impl Strategy<Value = Rpc> {
        let message = (
            topic(),
            proptest::collection::vec(any::<u8>(), 0..64),
            proptest::option::of(proptest::collection::vec(any::<u8>(), 0..8)),
        )
            .prop_map(|(topic, data, seqno)| RawMessage {
                seqno,
                ..RawMessage::anonymous(topic, data)
            });
        let prune = (
            topic(),
            proptest::option::of(any::<u64>()),
            proptest::collection::vec(any::<[u8; 32]>(), 0..3),
        )
            .prop_map(|(topic, backoff, keys)| Prune {
                topic,
                backoff,
                peers: keys
                    .into_iter()
                    .map(|k| {
                        let mut key = [2u8; 33];
                        key[1..].copy_from_slice(&k);
                        PeerInfo {
                            peer_id: Some(PeerId::from_public_key(&PublicKey::secp256k1(key))),
                            signed_peer_record: None,
                        }
                    })
                    .collect(),
            });
        let control = (
            proptest::collection::vec(
                (topic(), ids()).prop_map(|(topic, message_ids)| IHave { topic, message_ids }),
                0..3,
            ),
            proptest::collection::vec(ids().prop_map(|message_ids| IWant { message_ids }), 0..3),
            proptest::collection::vec(topic().prop_map(|topic| Graft { topic }), 0..3),
            proptest::collection::vec(prune, 0..3),
            proptest::collection::vec(
                ids().prop_map(|message_ids| IDontWant { message_ids }),
                0..3,
            ),
        )
            .prop_map(|(ihave, iwant, graft, prune, idontwant)| ControlMessage {
                ihave,
                iwant,
                graft,
                prune,
                idontwant,
            });
        (
            proptest::collection::vec(
                (any::<bool>(), topic())
                    .prop_map(|(subscribe, topic)| SubOpts { subscribe, topic }),
                0..3,
            ),
            proptest::collection::vec(message, 0..3),
            proptest::option::of(control),
        )
            .prop_map(|(subscriptions, publish, control)| Rpc {
                subscriptions,
                publish,
                control: control.filter(|c| !c.is_empty()),
            })
    }

    proptest! {
        #[test]
        fn round_trip(rpc in rpc()) {
            prop_assert_eq!(Rpc::decode(&rpc.encode()), Ok(rpc));
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = Rpc::decode(&bytes);
        }
    }
}
