//! Topics, message identifiers, protocol versions, and validation outcomes.

use std::fmt;

/// A pubsub topic, an opaque UTF-8 string.
///
/// Ethereum topics read `/eth2/<fork digest>/<name>/ssz_snappy`.
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Topic(String);

impl Topic {
    /// A topic from its string.
    #[must_use]
    pub fn new(topic: impl Into<String>) -> Self {
        Self(topic.into())
    }

    /// The topic string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Bytes of a message identifier.
///
/// The consensus p2p spec fixes 20 and requires rejecting any other size.
pub const MESSAGE_ID_LEN: usize = 20;

/// The identifier of a gossip message, derived from its content.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub [u8; MESSAGE_ID_LEN]);

impl MessageId {
    /// An identifier from wire bytes, or nothing when the length is not 20.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The first four bytes are enough to tell identifiers apart in logs.
        write!(f, "MessageId(")?;
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "..)")
    }
}

/// Which gossipsub revision a peer negotiated.
///
/// Later revisions add features while keeping the wire format compatible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolVersion {
    /// gossipsub v1.0: mesh, gossip, GRAFT and PRUNE.
    V1_0,
    /// gossipsub v1.1: peer exchange, backoff, scoring, extended validators.
    V1_1,
    /// gossipsub v1.2: IDONTWANT.
    V1_2,
}

impl ProtocolVersion {
    /// Every version this router speaks, in negotiation preference order.
    pub const ALL: [Self; 3] = [Self::V1_2, Self::V1_1, Self::V1_0];

    /// The multistream-select name.
    #[must_use]
    pub const fn protocol_id(self) -> &'static str {
        match self {
            Self::V1_0 => "/meshsub/1.0.0",
            Self::V1_1 => "/meshsub/1.1.0",
            Self::V1_2 => "/meshsub/1.2.0",
        }
    }

    /// The version a multistream-select name denotes.
    #[must_use]
    pub fn from_protocol_id(id: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|version| version.protocol_id() == id)
    }

    /// Whether the peer understands peer exchange and prune backoff.
    #[must_use]
    pub const fn supports_px(self) -> bool {
        matches!(self, Self::V1_1 | Self::V1_2)
    }

    /// Whether the peer understands IDONTWANT.
    #[must_use]
    pub const fn supports_idontwant(self) -> bool {
        matches!(self, Self::V1_2)
    }
}

/// The application's verdict on a received message.
///
/// See the extended validators section of gossipsub v1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// Valid: deliver it and forward it to the mesh.
    Accept,
    /// Invalid: drop it and penalize the peers that sent it.
    Reject,
    /// Not useful but not malicious: drop it without penalty.
    Ignore,
}
