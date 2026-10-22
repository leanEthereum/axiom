//! The control part of an RPC: gossip, mesh membership, and duplicate suppression.

use crate::{
    gossipsub::{MessageId, Topic},
    identity::PeerId,
    protobuf::{FieldReader, FieldWriter, ProtoMessage, ProtobufError},
};

/// Announces message identifiers held in the cache, for a topic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IHave {
    /// The topic the messages belong to.
    pub topic: Topic,
    /// Identifiers of recent messages.
    pub message_ids: Vec<MessageId>,
}

impl ProtoMessage for IHave {
    fn encode_to(&self, out: &mut Vec<u8>) {
        let mut fields = FieldWriter::new(out);
        fields.bytes(1, self.topic.as_str().as_bytes());
        for id in &self.message_ids {
            fields.bytes(2, &id.0);
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        // The entry opens like a GRAFT: its topic is field 1.
        let topic = Graft::decode(bytes)?.topic;
        let mut message_ids = Vec::new();
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            // Identifiers of any length other than 20 bytes are dropped.
            if field.number == 2
                && let Some(id) = MessageId::from_slice(field.bytes()?)
            {
                message_ids.push(id);
            }
        }
        Ok(Self { topic, message_ids })
    }
}

/// Asks for full messages announced in an IHAVE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IWant {
    /// Identifiers wanted.
    pub message_ids: Vec<MessageId>,
}

impl ProtoMessage for IWant {
    fn encode_to(&self, out: &mut Vec<u8>) {
        let mut fields = FieldWriter::new(out);
        for id in &self.message_ids {
            fields.bytes(1, &id.0);
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        let mut message_ids = Vec::new();
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            // Identifiers of any length other than 20 bytes are dropped.
            if field.number == 1
                && let Some(id) = MessageId::from_slice(field.bytes()?)
            {
                message_ids.push(id);
            }
        }
        Ok(Self { message_ids })
    }
}

/// Asks to join the receiver's mesh for a topic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graft {
    /// The topic.
    pub topic: Topic,
}

impl ProtoMessage for Graft {
    fn encode_to(&self, out: &mut Vec<u8>) {
        FieldWriter::new(out).bytes(1, self.topic.as_str().as_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        // The first topic field wins; anything after it is left unread.
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            if field.number == 1 {
                return Ok(Self {
                    topic: Topic::new(field.string()?),
                });
            }
        }
        Err(ProtobufError::MissingField(1))
    }
}

/// A peer offered as a replacement when pruning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// The peer's identifier.
    pub peer_id: Option<PeerId>,
    /// A signed record of the peer's addresses.
    pub signed_peer_record: Option<Vec<u8>>,
}

impl ProtoMessage for PeerInfo {
    fn encode_to(&self, out: &mut Vec<u8>) {
        let mut fields = FieldWriter::new(out);
        if let Some(id) = &self.peer_id {
            fields.bytes(1, id.as_bytes());
        }
        if let Some(record) = &self.signed_peer_record {
            fields.bytes(2, record);
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        let mut info = Self {
            peer_id: None,
            signed_peer_record: None,
        };
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match field.number {
                // A malformed identifier makes the record useless, not the RPC invalid.
                1 => info.peer_id = PeerId::from_bytes(field.bytes()?).ok(),
                2 => info.signed_peer_record = Some(field.bytes()?.to_vec()),
                _ => {}
            }
        }
        Ok(info)
    }
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

impl ProtoMessage for Prune {
    fn encode_to(&self, out: &mut Vec<u8>) {
        let mut fields = FieldWriter::new(out);
        fields.bytes(1, self.topic.as_str().as_bytes());
        for peer in &self.peers {
            fields.message(2, peer);
        }
        if let Some(backoff) = self.backoff {
            fields.varint(3, backoff);
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        let mut peers = Vec::new();
        let mut backoff = None;
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match field.number {
                2 => peers.push(PeerInfo::decode(field.bytes()?)?),
                3 => backoff = Some(field.varint()?),
                _ => {}
            }
        }
        Ok(Self {
            // The entry opens like a GRAFT: its topic is field 1.
            topic: Graft::decode(bytes)?.topic,
            peers,
            backoff,
        })
    }
}

/// Tells mesh peers not to forward messages already received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IDontWant {
    /// Identifiers not wanted.
    pub message_ids: Vec<MessageId>,
}

impl ProtoMessage for IDontWant {
    fn encode_to(&self, out: &mut Vec<u8>) {
        let mut fields = FieldWriter::new(out);
        for id in &self.message_ids {
            fields.bytes(1, &id.0);
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        // The layout is an IWANT's: identifiers repeated as field 1.
        let IWant { message_ids } = IWant::decode(bytes)?;
        Ok(Self { message_ids })
    }
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

impl ProtoMessage for ControlMessage {
    fn encode_to(&self, out: &mut Vec<u8>) {
        let mut fields = FieldWriter::new(out);
        for ihave in &self.ihave {
            fields.message(1, ihave);
        }
        for iwant in &self.iwant {
            fields.message(2, iwant);
        }
        for graft in &self.graft {
            fields.message(3, graft);
        }
        for prune in &self.prune {
            fields.message(4, prune);
        }
        for idontwant in &self.idontwant {
            fields.message(5, idontwant);
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
                1 => control.ihave.push(IHave::decode(body)?),
                2 => control.iwant.push(IWant::decode(body)?),
                3 => control.graft.push(Graft::decode(body)?),
                4 => control.prune.push(Prune::decode(body)?),
                _ => control.idontwant.push(IDontWant::decode(body)?),
            }
        }
        Ok(control)
    }
}
