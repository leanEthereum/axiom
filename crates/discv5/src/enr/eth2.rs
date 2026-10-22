//! The consensus fields of a record: fork, subnets, custody, and next fork digest.
//!
//! See `specs/phase0/p2p-interface.md`, `specs/altair/p2p-interface.md`,
//! and `specs/fulu/p2p-interface.md`, section "ENR structure".

use axiom_rlp::Decoder;
use axiom_ssz::{BitVector, Const, Container, DecodeError, FieldDecoder, FieldVisitor, Ssz};
use axiom_types::{Epoch, ForkDigest, Version};

use super::raw_value::RawValue;

/// Key of the fork identifier, an SSZ container in a 16-byte string.
pub(crate) const KEY_ETH2: &[u8] = b"eth2";

/// Key of the attestation subnet bitfield.
pub(crate) const KEY_ATTNETS: &[u8] = b"attnets";

/// Key of the sync committee subnet bitfield.
pub(crate) const KEY_SYNCNETS: &[u8] = b"syncnets";

/// Key of the custody group count, Fulu.
pub(crate) const KEY_CGC: &[u8] = b"cgc";

/// Key of the next fork digest, Fulu.
pub(crate) const KEY_NFD: &[u8] = b"nfd";

/// Attestation subnets a node subscribes to long-term: ATTESTATION_SUBNET_COUNT bits.
pub type Attnets = BitVector<Const<64>>;

/// Sync committee subnets a node subscribes to: SYNC_COMMITTEE_SUBNET_COUNT bits.
pub type Syncnets = BitVector<Const<4>>;

/// The fork a node follows and the next one it expects.
///
/// See `specs/phase0/p2p-interface.md`, "eth2 field".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EnrForkId {
    /// Digest of the current fork and the genesis validators root.
    pub fork_digest: ForkDigest,
    /// Version in effect at the next fork epoch.
    pub next_fork_version: Version,
    /// Epoch of the next planned fork, regular or blob-parameters-only.
    pub next_fork_epoch: Epoch,
}

impl Container for EnrForkId {
    const FIELDS: &'static [Option<usize>] = &[
        ForkDigest::FIXED_SIZE,
        Version::FIXED_SIZE,
        Epoch::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        // Field order is the spec's.
        visitor.field(&self.fork_digest);
        visitor.field(&self.next_fork_version);
        visitor.field(&self.next_fork_epoch);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        // Field order is the spec's.
        Ok(Self {
            fork_digest: fields.field()?,
            next_fork_version: fields.field()?,
            next_fork_epoch: fields.field()?,
        })
    }
}

/// The consensus fields of a record, each absent when missing or malformed.
///
/// Unknown or broken entries never void a record, per EIP-778.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Eth2Fields {
    /// The fork identifier.
    pub fork_id: Option<EnrForkId>,
    /// Long-lived attestation subnets.
    pub attnets: Option<Attnets>,
    /// Sync committee subnets.
    pub syncnets: Option<Syncnets>,
    /// Custody groups the node serves.
    pub custody_group_count: Option<u64>,
    /// Digest of the next scheduled fork.
    pub next_fork_digest: Option<ForkDigest>,
}

impl Eth2Fields {
    /// Reads the consensus keys through a lookup of raw values by key.
    pub(crate) fn read<'a>(value: impl Fn(&[u8]) -> Option<&'a [u8]>) -> Self {
        // SSZ values sit inside RLP strings; the custody count is a plain RLP integer.
        Self {
            fork_id: value(KEY_ETH2).and_then(|raw| RawValue(raw).ssz()),
            attnets: value(KEY_ATTNETS).and_then(|raw| RawValue(raw).ssz()),
            syncnets: value(KEY_SYNCNETS).and_then(|raw| RawValue(raw).ssz()),
            custody_group_count: value(KEY_CGC).and_then(|raw| {
                let mut decoder = Decoder::new(raw);
                let count = decoder.uint().ok()?;
                decoder.finish().ok()?;
                Some(count)
            }),
            next_fork_digest: value(KEY_NFD).and_then(|raw| RawValue(raw).ssz()),
        }
    }

    /// Whether the node subscribes to an attestation subnet.
    #[must_use]
    pub fn on_attestation_subnet(&self, subnet: usize) -> bool {
        // A missing bitfield or an out-of-range subnet reads as unsubscribed.
        self.attnets
            .as_ref()
            .and_then(|bits| bits.get(subnet))
            .unwrap_or(false)
    }

    /// Whether the node subscribes to a sync committee subnet.
    #[must_use]
    pub fn on_sync_subnet(&self, subnet: usize) -> bool {
        // A missing bitfield or an out-of-range subnet reads as unsubscribed.
        self.syncnets
            .as_ref()
            .and_then(|bits| bits.get(subnet))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_id_is_sixteen_bytes() {
        // Digest, then version, then the epoch as 8 little-endian bytes.
        let fork_id = EnrForkId {
            fork_digest: ForkDigest([1, 2, 3, 4]),
            next_fork_version: Version([5, 6, 7, 8]),
            next_fork_epoch: Epoch(0x0102),
        };
        assert_eq!(
            fork_id.encode(),
            [1, 2, 3, 4, 5, 6, 7, 8, 0x02, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(EnrForkId::decode(&fork_id.encode()), Ok(fork_id));
    }

    #[test]
    fn malformed_values_read_as_absent() {
        // A 3-byte nfd, a 9-byte attnets, and a padded cgc are all ignored.
        let entries: [(&[u8], &[u8]); 3] = [
            (KEY_NFD, &[0x83, 1, 2, 3]),
            (KEY_ATTNETS, &[0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (KEY_CGC, &[0x82, 0x00, 0x08]),
        ];
        let fields = Eth2Fields::read(|key| {
            entries
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, raw)| *raw)
        });
        assert_eq!(fields, Eth2Fields::default());
    }

    #[test]
    fn subnet_queries() {
        // Subnet 5 of 64 is set, sync subnet 2 of 4 is set.
        let mut attnets = Attnets::new();
        attnets.set(5, true);
        let mut syncnets = Syncnets::new();
        syncnets.set(2, true);
        let fields = Eth2Fields {
            attnets: Some(attnets),
            syncnets: Some(syncnets),
            ..Eth2Fields::default()
        };
        assert!(fields.on_attestation_subnet(5));
        assert!(!fields.on_attestation_subnet(6));
        // Out-of-range subnets are never subscribed.
        assert!(!fields.on_attestation_subnet(64));
        assert!(fields.on_sync_subnet(2));
        assert!(!fields.on_sync_subnet(3));
    }
}
