//! The Ethereum gossip encoding: snappy blocks, size bounds, and message identifiers.

use axiom_snappy::{SnappyError, raw};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::gossipsub::{MESSAGE_ID_LEN, MessageId, Topic};

/// MAX_PAYLOAD_SIZE of the Fulu configuration: 10 MiB, for gossip payloads and RPC chunks.
pub const MAX_PAYLOAD_SIZE: u64 = 10 * 1024 * 1024;

/// MESSAGE_DOMAIN_VALID_SNAPPY: separates identifiers of decodable payloads.
pub const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// MESSAGE_DOMAIN_INVALID_SNAPPY: separates identifiers of undecodable payloads.
pub const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// Worst-case snappy output for an input of n bytes: 32 + n + n / 6.
///
/// The phase0 p2p-interface spec takes the bound from snappy.cc.
#[must_use]
pub const fn max_compressed_len(n: u64) -> u64 {
    32 + n + n / 6
}

/// The ssz_snappy gossip encoding under one payload limit.
///
/// A payload travels as one raw snappy block, with no framing.
/// See `specs/phase0/p2p-interface.md`, encodings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GossipEncoding {
    /// The largest decompressed payload accepted, MAX_PAYLOAD_SIZE.
    max_payload_size: u64,
}

impl GossipEncoding {
    /// The encoding under a payload limit.
    #[must_use]
    pub const fn new(max_payload_size: u64) -> Self {
        Self { max_payload_size }
    }

    /// Largest gossip RPC frame: the compressed payload bound plus 1 KiB of framing, at least 1 MiB.
    #[must_use]
    pub fn max_message_size(self) -> usize {
        let bound = (max_compressed_len(self.max_payload_size) + 1024).max(1024 * 1024);
        usize::try_from(bound).unwrap_or(usize::MAX)
    }

    /// Compresses an SSZ payload into one raw snappy block.
    #[must_use]
    pub fn encode(self, ssz: &[u8]) -> Vec<u8> {
        raw::compress(ssz)
    }

    /// Decompresses a gossip payload, enforcing both size limits of the spec.
    pub fn decode(self, data: &[u8]) -> Result<Vec<u8>, GossipDecodeError> {
        // The compressed size is bounded before any work is done.
        let max_compressed = max_compressed_len(self.max_payload_size);
        if data.len() as u64 > max_compressed {
            return Err(GossipDecodeError::CompressedTooLarge {
                len: data.len(),
                max: max_compressed,
            });
        }
        // The decompressed size is checked from the preamble, before allocation.
        let max = usize::try_from(self.max_payload_size).unwrap_or(usize::MAX);
        raw::decompress(data, max).map_err(GossipDecodeError::Snappy)
    }

    /// The identifier of a gossip message, as Altair and later forks define it.
    ///
    /// ```text
    /// valid snappy:    SHA256(VALID_DOMAIN   || len(topic) as u64 LE || topic || decompressed)[:20]
    /// invalid snappy:  SHA256(INVALID_DOMAIN || len(topic) as u64 LE || topic || raw data)[:20]
    /// ```
    ///
    /// Two cases exist because distinct compressions may decode to one payload.
    /// Hashing the decompressed bytes gives them one identifier.
    /// The spec decides validity under MAX_PAYLOAD_SIZE, whatever the configured limit.
    /// See `specs/altair/p2p-interface.md`, topics and messages.
    #[must_use]
    pub fn message_id(topic: &Topic, data: &[u8]) -> MessageId {
        let topic = topic.as_str().as_bytes();
        let mut hasher = Sha256::new();
        // A payload that decompresses within the bound is hashed decompressed.
        let decompressed = raw::decompressed_len(data)
            .ok()
            .filter(|&len| len as u64 <= MAX_PAYLOAD_SIZE)
            .and_then(|_| raw::decompress(data, MAX_PAYLOAD_SIZE as usize).ok());
        match &decompressed {
            Some(_) => hasher.update(MESSAGE_DOMAIN_VALID_SNAPPY),
            None => hasher.update(MESSAGE_DOMAIN_INVALID_SNAPPY),
        }
        hasher.update((topic.len() as u64).to_le_bytes());
        hasher.update(topic);
        hasher.update(decompressed.as_deref().unwrap_or(data));
        let digest = hasher.finalize();
        let mut id = [0u8; MESSAGE_ID_LEN];
        id.copy_from_slice(&digest[..MESSAGE_ID_LEN]);
        MessageId(id)
    }
}

impl Default for GossipEncoding {
    /// The encoding under the Fulu MAX_PAYLOAD_SIZE.
    fn default() -> Self {
        Self::new(MAX_PAYLOAD_SIZE)
    }
}

/// A gossip payload that breaks the encoding rules.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum GossipDecodeError {
    /// The compressed payload exceeds the worst case for the largest payload.
    #[error("compressed payload of {len} bytes exceeds {max}")]
    CompressedTooLarge {
        /// Compressed length.
        len: usize,
        /// Largest compressed length allowed.
        max: u64,
    },
    /// The payload is not a valid snappy block within the size bound.
    #[error("invalid snappy payload: {0}")]
    Snappy(#[source] SnappyError),
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn message_id_of_valid_snappy() {
        let topic = Topic::new("/eth2/00000000/beacon_block/ssz_snappy");
        let payload = b"block".repeat(4);
        let data = GossipEncoding::default().encode(&payload);

        // Recompute the spec formula by hand.
        //
        //     SHA256(01000000 || 38 as u64 LE || topic || payload)[:20]
        let mut preimage = vec![0x01, 0, 0, 0];
        preimage.extend_from_slice(&38u64.to_le_bytes());
        preimage.extend_from_slice(topic.as_str().as_bytes());
        preimage.extend_from_slice(&payload);
        let expected = &Sha256::digest(&preimage)[..20];
        assert_eq!(GossipEncoding::message_id(&topic, &data).0, expected);
    }

    #[test]
    fn message_id_of_invalid_snappy() {
        let topic = Topic::new("t");
        // 0xff 0xff 0xff 0xff 0xff is a truncated varint preamble: not snappy.
        let data = [0xff; 5];
        let mut preimage = vec![0, 0, 0, 0];
        preimage.extend_from_slice(&1u64.to_le_bytes());
        preimage.push(b't');
        preimage.extend_from_slice(&data);
        assert_eq!(
            GossipEncoding::message_id(&topic, &data).0,
            &Sha256::digest(&preimage)[..20]
        );
    }

    #[test]
    fn size_bounds() {
        // 10 MiB payload → 32 + 10485760 + 1747626 = 12233418 compressed.
        assert_eq!(max_compressed_len(MAX_PAYLOAD_SIZE), 12_233_418);
        // Plus 1024 bytes of framing.
        assert_eq!(
            GossipEncoding::new(MAX_PAYLOAD_SIZE).max_message_size(),
            12_234_442
        );
        // A tiny payload bound still allows 1 MiB frames.
        assert_eq!(GossipEncoding::new(10).max_message_size(), 1024 * 1024);
        // A 100-byte payload against a 10-byte bound is rejected from the preamble.
        let data = GossipEncoding::default().encode(&[0; 100]);
        assert!(matches!(
            GossipEncoding::new(10).decode(&data),
            Err(GossipDecodeError::CompressedTooLarge { .. } | GossipDecodeError::Snappy(_))
        ));
    }

    proptest! {
        #[test]
        fn round_trip(payload in proptest::collection::vec(any::<u8>(), 0..2048)) {
            prop_assert_eq!(GossipEncoding::default().decode(&GossipEncoding::default().encode(&payload)), Ok(payload));
        }

        #[test]
        fn garbage_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = GossipEncoding::new(1024).decode(&data);
            let _ = GossipEncoding::message_id(&Topic::new("t"), &data);
        }
    }
}
