//! Req/resp protocol identifiers and their SSZ size bounds.

use std::{fmt, ops::RangeInclusive};

/// The prefix every consensus req/resp protocol shares.
const PREFIX: &str = "/eth2/beacon_chain/req/";

/// A req/resp method at one schema version, with the ssz_snappy encoding.
///
/// ```text
/// /eth2/beacon_chain/req/<name>/<version>/ssz_snappy
///
/// example: /eth2/beacon_chain/req/status/2/ssz_snappy
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    /// Chain status handshake, phase0.
    StatusV1,
    /// Chain status with the earliest available slot, Fulu.
    StatusV2,
    /// Disconnection notice, phase0.
    GoodbyeV1,
    /// Blocks in a slot range, Altair schema with fork context.
    BeaconBlocksByRangeV2,
    /// Blocks by root, Altair schema with fork context.
    BeaconBlocksByRootV2,
    /// Blob sidecars in a slot range, Deneb.
    BlobSidecarsByRangeV1,
    /// Blob sidecars by identifier, Deneb.
    BlobSidecarsByRootV1,
    /// Data column sidecars in a slot range, Fulu.
    DataColumnSidecarsByRangeV1,
    /// Data column sidecars by block root and column, Fulu.
    DataColumnSidecarsByRootV1,
    /// Blocks along the ancestry of a root, Fulu.
    BeaconBlocksByHeadV1,
    /// Metadata sequence number exchange, phase0.
    PingV1,
    /// Metadata with sync committee subnets, Altair.
    MetaDataV2,
    /// Metadata with the custody group count, Fulu.
    MetaDataV3,
}

impl Protocol {
    /// Every supported protocol, newest versions of a method first.
    pub const ALL: [Self; 13] = [
        Self::StatusV2,
        Self::StatusV1,
        Self::GoodbyeV1,
        Self::BeaconBlocksByRangeV2,
        Self::BeaconBlocksByRootV2,
        Self::BlobSidecarsByRangeV1,
        Self::BlobSidecarsByRootV1,
        Self::DataColumnSidecarsByRangeV1,
        Self::DataColumnSidecarsByRootV1,
        Self::BeaconBlocksByHeadV1,
        Self::PingV1,
        Self::MetaDataV3,
        Self::MetaDataV2,
    ];

    /// The full multistream-select name.
    #[must_use]
    pub const fn protocol_id(self) -> &'static str {
        match self {
            Self::StatusV1 => "/eth2/beacon_chain/req/status/1/ssz_snappy",
            Self::StatusV2 => "/eth2/beacon_chain/req/status/2/ssz_snappy",
            Self::GoodbyeV1 => "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
            Self::BeaconBlocksByRangeV2 => {
                "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"
            }
            Self::BeaconBlocksByRootV2 => {
                "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy"
            }
            Self::BlobSidecarsByRangeV1 => {
                "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy"
            }
            Self::BlobSidecarsByRootV1 => {
                "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy"
            }
            Self::DataColumnSidecarsByRangeV1 => {
                "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy"
            }
            Self::DataColumnSidecarsByRootV1 => {
                "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy"
            }
            Self::BeaconBlocksByHeadV1 => {
                "/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy"
            }
            Self::PingV1 => "/eth2/beacon_chain/req/ping/1/ssz_snappy",
            Self::MetaDataV2 => "/eth2/beacon_chain/req/metadata/2/ssz_snappy",
            Self::MetaDataV3 => "/eth2/beacon_chain/req/metadata/3/ssz_snappy",
        }
    }

    /// The protocol a multistream-select name denotes, compared exactly as the spec requires.
    #[must_use]
    pub fn from_protocol_id(id: &str) -> Option<Self> {
        // Cheap reject of foreign names before the table scan.
        if !id.starts_with(PREFIX) {
            return None;
        }
        Self::ALL
            .into_iter()
            .find(|protocol| protocol.protocol_id() == id)
    }

    /// Whether success chunks carry a 4-byte fork digest before the length.
    ///
    /// Methods whose payload type changes across forks use the ForkDigest-context.
    #[must_use]
    pub const fn has_context_bytes(self) -> bool {
        matches!(
            self,
            Self::BeaconBlocksByRangeV2
                | Self::BeaconBlocksByRootV2
                | Self::BlobSidecarsByRangeV1
                | Self::BlobSidecarsByRootV1
                | Self::DataColumnSidecarsByRangeV1
                | Self::DataColumnSidecarsByRootV1
                | Self::BeaconBlocksByHeadV1
        )
    }

    /// Whether the response is exactly one chunk rather than a list of them.
    #[must_use]
    pub const fn has_single_response(self) -> bool {
        matches!(
            self,
            Self::StatusV1
                | Self::StatusV2
                | Self::GoodbyeV1
                | Self::PingV1
                | Self::MetaDataV2
                | Self::MetaDataV3
        )
    }

    /// Whether the request carries no content at all.
    #[must_use]
    pub const fn has_empty_request(self) -> bool {
        matches!(self, Self::MetaDataV2 | Self::MetaDataV3)
    }

    /// The SSZ length range of a valid request, from the mainnet and minimal presets.
    ///
    /// The range spans both presets where they differ.
    #[must_use]
    pub const fn request_bounds(self) -> RangeInclusive<u64> {
        match self {
            // fork_digest 4 + finalized_root 32 + finalized_epoch 8 + head_root 32 + head_slot 8.
            Self::StatusV1 => 84..=84,
            // StatusV1 + earliest_available_slot 8.
            Self::StatusV2 => 92..=92,
            // A single uint64.
            Self::GoodbyeV1 | Self::PingV1 => 8..=8,
            // start_slot 8 + count 8 + step 8.
            Self::BeaconBlocksByRangeV2 => 24..=24,
            // Up to MAX_REQUEST_BLOCKS_DENEB = 128 roots of 32 bytes.
            Self::BeaconBlocksByRootV2 => 0..=128 * 32,
            // start_slot 8 + count 8.
            Self::BlobSidecarsByRangeV1 => 16..=16,
            // Up to MAX_REQUEST_BLOB_SIDECARS_ELECTRA = 1152 identifiers of root 32 + index 8.
            Self::BlobSidecarsByRootV1 => 0..=1152 * 40,
            // start_slot 8 + count 8 + offset 4, then up to NUMBER_OF_COLUMNS = 128 indices.
            Self::DataColumnSidecarsByRangeV1 => 20..=20 + 128 * 8,
            // Up to 128 identifiers: offset 4 + root 32 + offset 4 + up to 128 indices.
            Self::DataColumnSidecarsByRootV1 => 0..=128 * (4 + 32 + 4 + 128 * 8),
            // beacon_root 32 + count 8.
            Self::BeaconBlocksByHeadV1 => 40..=40,
            // No request content.
            Self::MetaDataV2 | Self::MetaDataV3 => 0..=0,
        }
    }

    /// The SSZ length range of a valid success chunk, capped by the payload limit.
    #[must_use]
    pub fn response_bounds(self, max_payload_size: u64) -> RangeInclusive<u64> {
        let (min, max) = match self {
            Self::StatusV1 => (84, 84),
            Self::StatusV2 => (92, 92),
            Self::GoodbyeV1 | Self::PingV1 => (8, 8),
            // seq_number 8 + attnets 8 + syncnets 1.
            Self::MetaDataV2 => (17, 17),
            // MetaDataV2 + custody_group_count 8.
            Self::MetaDataV3 => (25, 25),
            // A signed block: message offset 4 + signature 96, then the block.
            Self::BeaconBlocksByRangeV2
            | Self::BeaconBlocksByRootV2
            | Self::BeaconBlocksByHeadV1 => (100, u64::MAX),
            // A blob sidecar: 131072 blob + 8 + 48 + 48 + 208 header + depth * 32 proof.
            //
            //     minimal depth 10 → 131704,  mainnet depth 17 → 131928
            Self::BlobSidecarsByRangeV1 | Self::BlobSidecarsByRootV1 => (131_704, 131_928),
            // A data column sidecar: index 8 + three offsets 12 + header 208 + proof 4 * 32.
            Self::DataColumnSidecarsByRangeV1 | Self::DataColumnSidecarsByRootV1 => (356, u64::MAX),
        };
        min.min(max_payload_size)..=max.min(max_payload_size)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.protocol_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_round_trip() {
        for protocol in Protocol::ALL {
            assert_eq!(
                Protocol::from_protocol_id(protocol.protocol_id()),
                Some(protocol)
            );
        }
        // Exact equality: a trailing slash or other encoding is a different protocol.
        assert_eq!(
            Protocol::from_protocol_id("/eth2/beacon_chain/req/status/2/ssz"),
            None
        );
        assert_eq!(Protocol::from_protocol_id("/meshsub/1.2.0"), None);
    }

    #[test]
    fn response_bounds_respect_the_payload_limit() {
        // Blocks have no type bound below 10 MiB, so the limit applies.
        assert_eq!(
            Protocol::BeaconBlocksByRangeV2.response_bounds(10_485_760),
            100..=10_485_760
        );
        // A fixed-size status is unaffected.
        assert_eq!(Protocol::StatusV2.response_bounds(10_485_760), 92..=92);
    }
}
