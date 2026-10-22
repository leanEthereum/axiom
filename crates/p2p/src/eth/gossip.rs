//! The Ethereum gossip encoding: snappy blocks and size bounds.

use axiom_snappy::{SnappyError, raw};
use thiserror::Error;

/// MAX_PAYLOAD_SIZE of the Fulu configuration: 10 MiB, for gossip payloads and RPC chunks.
pub const MAX_PAYLOAD_SIZE: u64 = 10 * 1024 * 1024;

/// MESSAGE_DOMAIN_VALID_SNAPPY: separates identifiers of decodable payloads.
pub const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// MESSAGE_DOMAIN_INVALID_SNAPPY: separates identifiers of undecodable payloads.
pub const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

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
        // The phase0 p2p spec takes the compressed bound from snappy itself.
        (raw::max_compressed_len(self.max_payload_size as usize) + 1024).max(1024 * 1024)
    }

    /// Compresses an SSZ payload into one raw snappy block.
    #[must_use]
    pub fn encode(self, ssz: &[u8]) -> Vec<u8> {
        raw::compress(ssz)
    }

    /// Decompresses a gossip payload, enforcing both size limits of the spec.
    pub fn decode(self, data: &[u8]) -> Result<Vec<u8>, GossipDecodeError> {
        // The compressed size is bounded before any work is done.
        let max_compressed = raw::max_compressed_len(self.max_payload_size as usize) as u64;
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
    fn size_bounds() {
        // A 10 MiB payload compresses to at most 32 + 10485760 + 1747626 = 12233418 bytes.
        assert_eq!(
            raw::max_compressed_len(MAX_PAYLOAD_SIZE as usize),
            12_233_418
        );
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
            Err(GossipDecodeError::Snappy(_))
        ));
        // A 10-byte bound allows 32 + 10 + 1 = 43 compressed bytes, so 44 are refused unread.
        assert_eq!(
            GossipEncoding::new(10).decode(&[0; 44]),
            Err(GossipDecodeError::CompressedTooLarge { len: 44, max: 43 })
        );
    }

    proptest! {
        #[test]
        fn round_trip(payload in proptest::collection::vec(any::<u8>(), 0..2048)) {
            prop_assert_eq!(GossipEncoding::default().decode(&GossipEncoding::default().encode(&payload)), Ok(payload));
        }

        #[test]
        fn garbage_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = GossipEncoding::new(1024).decode(&data);
        }
    }
}
