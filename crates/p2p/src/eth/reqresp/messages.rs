//! The req/resp payloads this layer itself understands: status, metadata, goodbye.
//!
//! Block and sidecar payloads stay opaque bytes here; the node decodes them per fork.

use axiom_ssz::{BitVector, Const, Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};
use axiom_types::{Epoch, ForkDigest, Root, Slot};

/// The Status v2 handshake message, Fulu.
///
/// See `specs/fulu/p2p-interface.md`, Status v2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// The sender's current fork digest.
    pub fork_digest: ForkDigest,
    /// Root of the sender's finalized checkpoint.
    pub finalized_root: Root,
    /// Epoch of the sender's finalized checkpoint.
    pub finalized_epoch: Epoch,
    /// Root of the sender's head block.
    pub head_root: Root,
    /// Slot of the sender's head block.
    pub head_slot: Slot,
    /// Slot of the earliest block the sender can serve.
    pub earliest_available_slot: Slot,
}

impl Container for Status {
    const FIELDS: &'static [Option<usize>] = &[
        ForkDigest::FIXED_SIZE,
        Root::FIXED_SIZE,
        Epoch::FIXED_SIZE,
        Root::FIXED_SIZE,
        Slot::FIXED_SIZE,
        Slot::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.fork_digest);
        visitor.field(&self.finalized_root);
        visitor.field(&self.finalized_epoch);
        visitor.field(&self.head_root);
        visitor.field(&self.head_slot);
        visitor.field(&self.earliest_available_slot);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            fork_digest: fields.field()?,
            finalized_root: fields.field()?,
            finalized_epoch: fields.field()?,
            head_root: fields.field()?,
            head_slot: fields.field()?,
            earliest_available_slot: fields.field()?,
        })
    }
}

/// The Status v1 handshake message, phase0 to Electra.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatusV1 {
    /// The sender's current fork digest.
    pub fork_digest: ForkDigest,
    /// Root of the sender's finalized checkpoint.
    pub finalized_root: Root,
    /// Epoch of the sender's finalized checkpoint.
    pub finalized_epoch: Epoch,
    /// Root of the sender's head block.
    pub head_root: Root,
    /// Slot of the sender's head block.
    pub head_slot: Slot,
}

impl Container for StatusV1 {
    const FIELDS: &'static [Option<usize>] = &[
        ForkDigest::FIXED_SIZE,
        Root::FIXED_SIZE,
        Epoch::FIXED_SIZE,
        Root::FIXED_SIZE,
        Slot::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.fork_digest);
        visitor.field(&self.finalized_root);
        visitor.field(&self.finalized_epoch);
        visitor.field(&self.head_root);
        visitor.field(&self.head_slot);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            fork_digest: fields.field()?,
            finalized_root: fields.field()?,
            finalized_epoch: fields.field()?,
            head_root: fields.field()?,
            head_slot: fields.field()?,
        })
    }
}

/// Persistent attestation subnet subscriptions: ATTESTATION_SUBNET_COUNT = 64 bits.
pub type Attnets = BitVector<Const<64>>;

/// Persistent sync committee subnet subscriptions: SYNC_COMMITTEE_SUBNET_COUNT = 4 bits.
pub type Syncnets = BitVector<Const<4>>;

/// The node metadata of GetMetaData v3, Fulu.
///
/// See `specs/fulu/p2p-interface.md`, MetaData.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetaData {
    /// Incremented whenever another field changes.
    pub seq_number: u64,
    /// Long-lived attestation subnets.
    pub attnets: Attnets,
    /// Long-lived sync committee subnets.
    pub syncnets: Syncnets,
    /// Custody groups the node stores and serves.
    pub custody_group_count: u64,
}

impl Container for MetaData {
    const FIELDS: &'static [Option<usize>] = &[
        u64::FIXED_SIZE,
        Attnets::FIXED_SIZE,
        Syncnets::FIXED_SIZE,
        u64::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.seq_number);
        visitor.field(&self.attnets);
        visitor.field(&self.syncnets);
        visitor.field(&self.custody_group_count);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            seq_number: fields.field()?,
            attnets: fields.field()?,
            syncnets: fields.field()?,
            custody_group_count: fields.field()?,
        })
    }
}

/// The reason in a Goodbye request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GoodbyeReason(pub u64);

impl GoodbyeReason {
    /// The sender is shutting down.
    pub const CLIENT_SHUTDOWN: Self = Self(1);
    /// The peer is on another network or fork.
    pub const IRRELEVANT_NETWORK: Self = Self(2);
    /// The peer misbehaved or an error occurred.
    pub const FAULT: Self = Self(3);

    /// The 8-byte SSZ encoding: a bare uint64, not a container.
    #[must_use]
    pub const fn to_ssz(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_sizes_match_the_protocol_bounds() {
        // Status v2 is 92 bytes, v1 84, metadata v3 25: the req/resp bounds rely on it.
        assert_eq!(Status::default().encode().len(), 92);
        assert_eq!(StatusV1::default().encode().len(), 84);
        assert_eq!(MetaData::default().encode().len(), 25);
    }

    #[test]
    fn status_layout_and_round_trip() {
        let status = Status {
            fork_digest: ForkDigest([0xaa, 0xbb, 0xcc, 0xdd]),
            finalized_root: Root::from([1; 32]),
            finalized_epoch: Epoch(5),
            head_root: Root::from([2; 32]),
            head_slot: Slot(200),
            earliest_available_slot: Slot(64),
        };
        let bytes = status.encode();
        // Fields in order: digest 0..4, finalized root 4..36, epoch 36..44 LE.
        assert_eq!(&bytes[..4], &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(&bytes[36..44], &5u64.to_le_bytes());
        assert_eq!(&bytes[84..92], &64u64.to_le_bytes());
        assert_eq!(Status::decode(&bytes), Ok(status));
    }
}
