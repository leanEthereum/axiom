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

use super::{MessageId, Topic};
use crate::{
    identity::PeerId,
    protobuf::{
        FieldReader, ProtoMessage, ProtobufError, encode_bytes_field, encode_message_field,
        encode_varint_field,
    },
};

/// A message as it travels, before any validation.
///
/// Under the StrictNoSign policy, the four authorship fields must be absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawMessage {
    /// The author's peer identifier.
    pub from: Option<Vec<u8>>,
    /// The payload.
    pub data: Vec<u8>,
    /// The author's sequence number.
    pub seqno: Option<Vec<u8>>,
    /// The topic the message is published on.
    pub topic: Topic,
    /// The author's signature.
    pub signature: Option<Vec<u8>>,
    /// The author's public key, when the identifier does not embed it.
    pub key: Option<Vec<u8>>,
}

impl RawMessage {
    /// An unsigned, anonymous message, as Ethereum publishes them.
    #[must_use]
    pub const fn anonymous(topic: Topic, data: Vec<u8>) -> Self {
        Self {
            from: None,
            data,
            seqno: None,
            topic,
            signature: None,
            key: None,
        }
    }

    /// Whether the message obeys StrictNoSign: no author, sequence number, signature, or key.
    #[must_use]
    pub const fn is_strict_no_sign(&self) -> bool {
        self.from.is_none()
            && self.seqno.is_none()
            && self.signature.is_none()
            && self.key.is_none()
    }
}

impl ProtoMessage for RawMessage {
    fn encode_to(&self, out: &mut Vec<u8>) {
        if let Some(from) = &self.from {
            encode_bytes_field(1, from, out);
        }
        encode_bytes_field(2, &self.data, out);
        if let Some(seqno) = &self.seqno {
            encode_bytes_field(3, seqno, out);
        }
        encode_bytes_field(4, self.topic.as_str().as_bytes(), out);
        if let Some(signature) = &self.signature {
            encode_bytes_field(5, signature, out);
        }
        if let Some(key) = &self.key {
            encode_bytes_field(6, key, out);
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        let mut message = Self::default();
        let mut topic = None;
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match field.number {
                1 => message.from = Some(field.bytes()?.to_vec()),
                2 => message.data = field.bytes()?.to_vec(),
                3 => message.seqno = Some(field.bytes()?.to_vec()),
                4 => topic = Some(Topic::new(field.string()?)),
                5 => message.signature = Some(field.bytes()?.to_vec()),
                6 => message.key = Some(field.bytes()?.to_vec()),
                _ => {}
            }
        }
        // The topic is the one required field of the schema.
        message.topic = topic.ok_or(ProtobufError::MissingField(4))?;
        Ok(message)
    }
}

/// A subscription change announced to a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubOpts {
    /// Whether the sender joins or leaves the topic.
    pub subscribe: bool,
    /// The topic.
    pub topic: Topic,
}

impl ProtoMessage for SubOpts {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_varint_field(1, u64::from(self.subscribe), out);
        encode_bytes_field(2, self.topic.as_str().as_bytes(), out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        let mut subscribe = false;
        let mut topic = None;
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match field.number {
                1 => subscribe = field.bool()?,
                2 => topic = Some(Topic::new(field.string()?)),
                _ => {}
            }
        }
        // A subscription without a topic carries no information.
        Ok(Self {
            subscribe,
            topic: topic.ok_or(ProtobufError::MissingField(2))?,
        })
    }
}

/// Announces message identifiers held in the cache, for a topic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IHave {
    /// The topic the messages belong to.
    pub topic: Topic,
    /// Identifiers of recent messages.
    pub message_ids: Vec<MessageId>,
}

/// Asks for full messages announced in an IHAVE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IWant {
    /// Identifiers wanted.
    pub message_ids: Vec<MessageId>,
}

/// Asks to join the receiver's mesh for a topic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graft {
    /// The topic.
    pub topic: Topic,
}

/// A peer offered as a replacement when pruning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// The peer's identifier.
    pub peer_id: Option<PeerId>,
    /// A signed record of the peer's addresses.
    pub signed_peer_record: Option<Vec<u8>>,
}

/// Removes the sender from the receiver's mesh for a topic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prune {
    /// The topic.
    pub topic: Topic,
    /// Replacement peers, for peer exchange.
    pub peers: Vec<PeerInfo>,
    /// Seconds before the receiver may graft again.
    pub backoff: Option<u64>,
}

/// Tells mesh peers not to forward messages already received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IDontWant {
    /// Identifiers not wanted.
    pub message_ids: Vec<MessageId>,
}

/// The control part of an RPC.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControlMessage {
    /// Gossip announcements.
    pub ihave: Vec<IHave>,
    /// Requests for announced messages.
    pub iwant: Vec<IWant>,
    /// Mesh join requests.
    pub graft: Vec<Graft>,
    /// Mesh departures.
    pub prune: Vec<Prune>,
    /// Duplicate suppression notices.
    pub idontwant: Vec<IDontWant>,
}

impl ControlMessage {
    /// Whether the message carries nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ihave.is_empty()
            && self.iwant.is_empty()
            && self.graft.is_empty()
            && self.prune.is_empty()
            && self.idontwant.is_empty()
    }
}

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

/// Appends a repeated identifier field.
fn encode_ids(number: u32, ids: &[MessageId], out: &mut Vec<u8>) {
    for id in ids {
        encode_bytes_field(number, &id.0, out);
    }
}

/// Appends a topic field.
fn encode_topic(number: u32, topic: &Topic, out: &mut Vec<u8>) {
    encode_bytes_field(number, topic.as_str().as_bytes(), out);
}

impl ProtoMessage for ControlMessage {
    fn encode_to(&self, out: &mut Vec<u8>) {
        // Each entry is a nested message, encoded into a scratch buffer for its length prefix.
        let mut entry = Vec::new();
        for ihave in &self.ihave {
            entry.clear();
            encode_topic(1, &ihave.topic, &mut entry);
            encode_ids(2, &ihave.message_ids, &mut entry);
            encode_bytes_field(1, &entry, out);
        }
        for iwant in &self.iwant {
            entry.clear();
            encode_ids(1, &iwant.message_ids, &mut entry);
            encode_bytes_field(2, &entry, out);
        }
        for graft in &self.graft {
            entry.clear();
            encode_topic(1, &graft.topic, &mut entry);
            encode_bytes_field(3, &entry, out);
        }
        for prune in &self.prune {
            entry.clear();
            encode_topic(1, &prune.topic, &mut entry);
            for peer in &prune.peers {
                // Peer records nest one level deeper.
                let mut info = Vec::new();
                if let Some(id) = &peer.peer_id {
                    encode_bytes_field(1, id.as_bytes(), &mut info);
                }
                if let Some(record) = &peer.signed_peer_record {
                    encode_bytes_field(2, record, &mut info);
                }
                encode_bytes_field(2, &info, &mut entry);
            }
            if let Some(backoff) = prune.backoff {
                encode_varint_field(3, backoff, &mut entry);
            }
            encode_bytes_field(4, &entry, out);
        }
        for idontwant in &self.idontwant {
            entry.clear();
            encode_ids(1, &idontwant.message_ids, &mut entry);
            encode_bytes_field(5, &entry, out);
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        let mut control = Self::default();
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            let body = match field.number {
                1..=5 => field.bytes()?,
                _ => continue,
            };
            match field.number {
                1 => control.ihave.push(decode_ihave(body)?),
                2 => control.iwant.push(IWant {
                    message_ids: decode_ids(body, 1)?,
                }),
                3 => control.graft.push(Graft {
                    topic: decode_topic(body)?,
                }),
                4 => control.prune.push(decode_prune(body)?),
                _ => control.idontwant.push(IDontWant {
                    message_ids: decode_ids(body, 1)?,
                }),
            }
        }
        Ok(control)
    }
}

/// Collects a repeated identifier field, dropping identifiers that are not 20 bytes.
fn decode_ids(body: &[u8], number: u32) -> Result<Vec<MessageId>, ProtobufError> {
    let mut ids = Vec::new();
    let mut reader = FieldReader::new(body);
    while let Some(field) = reader.next_field()? {
        if field.number == number
            && let Some(id) = MessageId::from_slice(field.bytes()?)
        {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// Reads the topic field, number 1, of a control entry.
fn decode_topic(body: &[u8]) -> Result<Topic, ProtobufError> {
    let mut reader = FieldReader::new(body);
    while let Some(field) = reader.next_field()? {
        if field.number == 1 {
            return Ok(Topic::new(field.string()?));
        }
    }
    Err(ProtobufError::MissingField(1))
}

/// Decodes an IHAVE entry.
fn decode_ihave(body: &[u8]) -> Result<IHave, ProtobufError> {
    Ok(IHave {
        topic: decode_topic(body)?,
        message_ids: decode_ids(body, 2)?,
    })
}

/// Decodes a PRUNE entry with its peer exchange records.
fn decode_prune(body: &[u8]) -> Result<Prune, ProtobufError> {
    let mut peers = Vec::new();
    let mut backoff = None;
    let mut reader = FieldReader::new(body);
    while let Some(field) = reader.next_field()? {
        match field.number {
            2 => {
                let mut info = PeerInfo {
                    peer_id: None,
                    signed_peer_record: None,
                };
                let mut inner = FieldReader::new(field.bytes()?);
                while let Some(field) = inner.next_field()? {
                    match field.number {
                        // A malformed identifier makes the record useless, not the RPC invalid.
                        1 => info.peer_id = PeerId::from_bytes(field.bytes()?).ok(),
                        2 => info.signed_peer_record = Some(field.bytes()?.to_vec()),
                        _ => {}
                    }
                }
                peers.push(info);
            }
            3 => backoff = Some(field.varint()?),
            _ => {}
        }
    }
    Ok(Prune {
        topic: decode_topic(body)?,
        peers,
        backoff,
    })
}

impl ProtoMessage for Rpc {
    fn encode_to(&self, out: &mut Vec<u8>) {
        for subscription in &self.subscriptions {
            encode_message_field(1, subscription, out);
        }
        for message in &self.publish {
            encode_message_field(2, message, out);
        }
        if let Some(control) = &self.control
            && !control.is_empty()
        {
            encode_message_field(3, control, out);
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
    use crate::identity::PublicKey;

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
        encode_bytes_field(1, &[1; 20], &mut iwant);
        encode_bytes_field(1, &[2; 19], &mut iwant);
        let mut control = Vec::new();
        encode_bytes_field(2, &iwant, &mut control);
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
