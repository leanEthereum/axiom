//! Full messages and subscription changes.

use crate::{
    gossipsub::Topic,
    protobuf::{FieldReader, FieldWriter, ProtoMessage, ProtobufError},
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
        let mut fields = FieldWriter::new(out);
        if let Some(from) = &self.from {
            fields.bytes(1, from);
        }
        fields.bytes(2, &self.data);
        if let Some(seqno) = &self.seqno {
            fields.bytes(3, seqno);
        }
        fields.bytes(4, self.topic.as_str().as_bytes());
        if let Some(signature) = &self.signature {
            fields.bytes(5, signature);
        }
        if let Some(key) = &self.key {
            fields.bytes(6, key);
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
        let mut fields = FieldWriter::new(out);
        fields.varint(1, u64::from(self.subscribe));
        fields.bytes(2, self.topic.as_str().as_bytes());
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
