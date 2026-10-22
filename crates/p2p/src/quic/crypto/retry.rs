//! The Retry integrity tag, per RFC 9001, section 5.8.
//!
//! The tag is AES-128-GCM over an empty plaintext with fixed public key and nonce.
//! Its associated data is the Retry pseudo-packet:
//!
//! ```text
//! original dcid length (1) | original dcid | Retry packet without its tag
//! ```
//!
//! Anyone can compute it, so it proves only that the sender saw the client's Initial.
//! That defeats off-path injection of Retry packets.

use axiom_crypto::aes::Aes128Gcm;

use crate::quic::{ConnectionId, packet::RETRY_TAG_LEN};

/// The fixed key of version 1.
const KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// The fixed nonce of version 1.
const NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// The integrity tag of a Retry packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetryTag([u8; RETRY_TAG_LEN]);

impl RetryTag {
    /// The tag over a Retry packet's bytes before the tag, for the client's original dcid.
    pub(crate) fn compute(original_dcid: &ConnectionId, packet_without_tag: &[u8]) -> Self {
        let mut pseudo = Vec::with_capacity(1 + original_dcid.len() + packet_without_tag.len());
        original_dcid.encode_with_length(&mut pseudo);
        pseudo.extend_from_slice(packet_without_tag);
        Self(Aes128Gcm::new(&KEY).seal_in_place_detached(&NONCE, &pseudo, &mut []))
    }

    /// Whether a received tag matches.
    ///
    /// The tag is public, so a variable-time comparison leaks nothing.
    pub(crate) fn matches(self, received: &[u8; RETRY_TAG_LEN]) -> bool {
        self.0 == *received
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::testing::hex;

    #[test]
    fn rfc_9001_appendix_a4() {
        // The Retry of RFC 9001, appendix A.4, sent for the client's dcid 8394c8f03e515708.
        let packet =
            hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
        let original = ConnectionId::new(&hex("8394c8f03e515708")).unwrap();
        let (body, tag) = packet.split_at(packet.len() - RETRY_TAG_LEN);
        let expected: [u8; RETRY_TAG_LEN] = tag.try_into().unwrap();
        assert_eq!(RetryTag::compute(&original, body).0, expected);
        assert!(RetryTag::compute(&original, body).matches(&expected));

        // Another original dcid gives another tag, so a forged Retry fails.
        let other = ConnectionId::new(&hex("8394c8f03e515709")).unwrap();
        assert!(!RetryTag::compute(&other, body).matches(&expected));
    }
}
