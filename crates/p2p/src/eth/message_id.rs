//! Gossip message identifiers, with the formula each fork's topics call for.

use std::sync::Arc;

use axiom_snappy::raw;
use axiom_types::{ForkDigest, ForkName};
use sha2::{Digest, Sha256};

use super::{
    GossipTopic,
    gossip::{MAX_PAYLOAD_SIZE, MESSAGE_DOMAIN_INVALID_SNAPPY, MESSAGE_DOMAIN_VALID_SNAPPY},
};
use crate::gossipsub::{MESSAGE_ID_LEN, MessageId, Topic};

/// Derives gossip message identifiers, choosing each topic's formula by its fork digest.
///
/// ```text
/// phase0, valid snappy:     SHA256(VALID_DOMAIN || decompressed)[:20]
/// phase0, invalid snappy:   SHA256(INVALID_DOMAIN || raw data)[:20]
/// Altair on, valid snappy:  SHA256(VALID_DOMAIN || le64(len(topic)) || topic || decompressed)[:20]
/// Altair on, invalid:       SHA256(INVALID_DOMAIN || le64(len(topic)) || topic || raw data)[:20]
/// ```
///
/// Two cases exist because distinct compressions may decode to one payload.
/// Hashing the decompressed bytes gives them one identifier.
/// The spec decides validity under MAX_PAYLOAD_SIZE, whatever the configured limit.
///
/// A digest the chain does not schedule takes the topic-aware formula.
/// See "Topics and messages" in the phase0 and Altair p2p specs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MessageIds {
    /// Digests whose topics hash the payload alone.
    payload_only: Arc<[ForkDigest]>,
}

impl MessageIds {
    /// The rules of a chain, from each scheduled digest and the fork it names.
    #[must_use]
    pub fn new(forks: impl IntoIterator<Item = (ForkDigest, ForkName)>) -> Self {
        Self {
            payload_only: forks
                .into_iter()
                .filter(|(_, fork)| !fork.message_id_hashes_topic())
                .map(|(digest, _)| digest)
                .collect(),
        }
    }

    /// The identifier of a message on a topic.
    #[must_use]
    pub fn id(&self, topic: &Topic, data: &[u8]) -> MessageId {
        let hashes_topic = self.payload_only.is_empty()
            || topic
                .as_str()
                .parse::<GossipTopic>()
                .map_or(true, |parsed| {
                    !self.payload_only.contains(&parsed.fork_digest)
                });

        // A payload that decompresses within the bound is hashed decompressed.
        let decompressed = raw::decompressed_len(data)
            .ok()
            .filter(|&len| len as u64 <= MAX_PAYLOAD_SIZE)
            .and_then(|_| raw::decompress(data, MAX_PAYLOAD_SIZE as usize).ok());
        let mut hasher = Sha256::new();
        match &decompressed {
            Some(_) => hasher.update(MESSAGE_DOMAIN_VALID_SNAPPY),
            None => hasher.update(MESSAGE_DOMAIN_INVALID_SNAPPY),
        }
        if hashes_topic {
            let topic = topic.as_str().as_bytes();
            hasher.update((topic.len() as u64).to_le_bytes());
            hasher.update(topic);
        }
        hasher.update(decompressed.as_deref().unwrap_or(data));
        let digest = hasher.finalize();
        let mut id = [0; MESSAGE_ID_LEN];
        id.copy_from_slice(&digest[..MESSAGE_ID_LEN]);
        MessageId(id)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::eth::{GossipEncoding, GossipKind};

    /// The first 20 bytes of SHA-256 over the concatenated parts.
    fn sha256_20(parts: &[&[u8]]) -> [u8; 20] {
        let digest = Sha256::digest(parts.concat());
        let mut id = [0; 20];
        id.copy_from_slice(&digest[..20]);
        id
    }

    /// A chain with phase0 under digest 0x01010101 and Altair under 0x02020202.
    fn chain() -> (MessageIds, Topic, Topic) {
        let phase0 = ForkDigest([1; 4]);
        let altair = ForkDigest([2; 4]);
        let ids = MessageIds::new([(phase0, ForkName::Phase0), (altair, ForkName::Altair)]);
        let topic = |fork_digest| {
            GossipTopic {
                fork_digest,
                kind: GossipKind::BeaconBlock,
            }
            .topic()
        };
        (ids, topic(phase0), topic(altair))
    }

    #[test]
    fn phase0_topics_hash_the_payload_alone() {
        let (ids, phase0, _) = chain();
        let payload = b"block".repeat(4);
        let data = GossipEncoding::default().encode(&payload);

        // Valid snappy: SHA256(01000000 || payload)[:20].
        let expected = sha256_20(&[&[1, 0, 0, 0], &payload]);
        assert_eq!(ids.id(&phase0, &data), MessageId(expected));

        // Invalid snappy: 0xff 0xff 0xff 0xff 0xff is a truncated varint preamble.
        // SHA256(00000000 || raw data)[:20].
        let garbage = [0xff; 5];
        let expected = sha256_20(&[&[0, 0, 0, 0], &garbage]);
        assert_eq!(ids.id(&phase0, &garbage), MessageId(expected));
    }

    #[test]
    fn altair_topics_hash_the_topic_too() {
        let (ids, _, altair) = chain();
        let payload = b"block".repeat(4);
        let data = GossipEncoding::default().encode(&payload);
        let name = altair.as_str().as_bytes();
        // "/eth2/02020202/beacon_block/ssz_snappy" is 38 bytes.
        assert_eq!(name.len(), 38);

        // Valid snappy: SHA256(01000000 || le64(38) || topic || payload)[:20].
        let expected = sha256_20(&[&[1, 0, 0, 0], &38_u64.to_le_bytes(), name, &payload]);
        assert_eq!(ids.id(&altair, &data), MessageId(expected));

        // Invalid snappy: SHA256(00000000 || le64(38) || topic || raw data)[:20].
        let garbage = [0xff; 5];
        let expected = sha256_20(&[&[0, 0, 0, 0], &38_u64.to_le_bytes(), name, &garbage]);
        assert_eq!(ids.id(&altair, &garbage), MessageId(expected));
    }

    #[test]
    fn unknown_digests_and_names_hash_the_topic() {
        let (ids, phase0, _) = chain();
        let data = [0xff; 5];
        let with_topic = |topic: &Topic| {
            let name = topic.as_str().as_bytes();
            MessageId(sha256_20(&[
                &[0, 0, 0, 0],
                &(name.len() as u64).to_le_bytes(),
                name,
                &data,
            ]))
        };

        // Digest 0x03030303 is not scheduled on this chain.
        let foreign = GossipTopic {
            fork_digest: ForkDigest([3; 4]),
            kind: GossipKind::BeaconBlock,
        }
        .topic();
        assert_eq!(ids.id(&foreign, &data), with_topic(&foreign));

        // A topic that is no consensus topic at all.
        let other = Topic::new("t");
        assert_eq!(ids.id(&other, &data), with_topic(&other));

        // With no schedule, even the phase0 digest hashes the topic.
        assert_eq!(
            MessageIds::default().id(&phase0, &data),
            with_topic(&phase0)
        );
    }

    proptest! {
        #[test]
        fn garbage_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let (ids, phase0, altair) = chain();
            let _ = ids.id(&phase0, &data);
            let _ = ids.id(&altair, &data);
        }
    }
}
