//! Ethereum node records, EIP-778, with the consensus entries of the p2p spec.

mod builder;
mod endpoint;
mod error;
mod eth2;
mod record;

pub use builder::EnrBuilder;
pub use endpoint::Endpoints;
pub use error::EnrError;
pub use eth2::{Attnets, EnrForkId, Eth2Fields, Syncnets};
pub use record::{Enr, MAX_RECORD_LEN};

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use axiom_crypto::secp256k1::SecretKey;
    use axiom_rlp::{Encoder, RlpError};
    use axiom_types::{Epoch, ForkDigest, Version};
    use proptest::prelude::*;

    use super::*;
    use crate::{base64::Base64Url, node_id::NodeId};

    /// The record of the EIP-778 test vector.
    const EIP778_TEXT: &str = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";

    /// The private key of the EIP-778 test vector.
    const EIP778_KEY: [u8; 32] = [
        0xb7, 0x1c, 0x71, 0xa6, 0x7e, 0x11, 0x77, 0xad, 0x4e, 0x90, 0x16, 0x95, 0xe1, 0xb4, 0xb9,
        0xee, 0x17, 0xae, 0x16, 0xc6, 0x66, 0x8d, 0x31, 0x3e, 0xac, 0x2f, 0x96, 0xdb, 0xcd, 0xa3,
        0xf2, 0x91,
    ];

    #[test]
    fn eip778_vector_decodes() {
        // Fixture state: the vector advertises 127.0.0.1, UDP 30303, at sequence 1.
        let enr: Enr = EIP778_TEXT.parse().unwrap();
        assert_eq!(enr.seq(), 1);
        assert_eq!(
            enr.node_id().to_string(),
            "a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
        );
        assert_eq!(
            *enr.endpoints(),
            Endpoints {
                ip4: Some(Ipv4Addr::LOCALHOST),
                udp4: Some(30303),
                ..Endpoints::default()
            }
        );
        // The signature is the vector's first list element.
        assert_eq!(&enr.as_bytes()[4..8], &[0x70, 0x98, 0xad, 0x86]);
        assert_eq!(enr.to_string(), EIP778_TEXT);
    }

    #[test]
    fn eip778_vector_signs_identically() {
        // RFC 6979 nonces are deterministic, so signing the same content reproduces the vector.
        let key = SecretKey::from_bytes(&EIP778_KEY).unwrap();
        let enr = Enr::builder()
            .ip4(Ipv4Addr::LOCALHOST)
            .udp4(30303)
            .build(&key)
            .unwrap();
        assert_eq!(enr.to_string(), EIP778_TEXT);
    }

    #[test]
    fn tampering_breaks_the_signature() {
        // Mutation: flip the last byte, the low byte of the UDP port.
        let mut bytes = Base64Url::decode(&EIP778_TEXT[4..]).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(matches!(
            Enr::decode(&bytes),
            Err(EnrError::InvalidSignature(_))
        ));
    }

    #[test]
    fn eth2_fields_round_trip() {
        // A Fulu record: fork id, subnets 1 and 63, sync subnet 0, 8 custody groups, a next digest.
        let key = SecretKey::from_bytes(&[3; 32]).unwrap();
        let fork_id = EnrForkId {
            fork_digest: ForkDigest([0xaa, 0xbb, 0xcc, 0xdd]),
            next_fork_version: Version([7, 0, 0, 0]),
            next_fork_epoch: Epoch(u64::MAX),
        };
        let mut attnets = Attnets::new();
        attnets.set(1, true);
        attnets.set(63, true);
        let mut syncnets = Syncnets::new();
        syncnets.set(0, true);
        let enr = Enr::builder()
            .ip4(Ipv4Addr::new(10, 0, 0, 1))
            .udp4(9000)
            .tcp4(9001)
            .fork_id(&fork_id)
            .attnets(&attnets)
            .syncnets(&syncnets)
            .custody_group_count(8)
            .next_fork_digest(ForkDigest([1, 2, 3, 4]))
            .build(&key)
            .unwrap();
        let decoded = Enr::decode(enr.as_bytes()).unwrap();
        assert_eq!(
            *decoded.eth2(),
            Eth2Fields {
                fork_id: Some(fork_id),
                attnets: Some(attnets),
                syncnets: Some(syncnets),
                custody_group_count: Some(8),
                next_fork_digest: Some(ForkDigest([1, 2, 3, 4])),
            }
        );
        // The custody count is a bare integer: 0x08.
        assert_eq!(decoded.get_raw(b"cgc"), Some(&[0x08][..]));
        // Zero custody groups encode as the empty string, 0x80.
        let zero = Enr::builder().custody_group_count(0).build(&key).unwrap();
        assert_eq!(zero.get_raw(b"cgc"), Some(&[0x80][..]));
        assert_eq!(zero.eth2().custody_group_count, Some(0));
    }

    #[test]
    fn updates_bump_the_sequence() {
        // Re-signing keeps entries and moves from sequence 1 to 2.
        let key = SecretKey::from_bytes(&EIP778_KEY).unwrap();
        let enr: Enr = EIP778_TEXT.parse().unwrap();
        let updated = enr.to_builder().udp4(30304).build(&key).unwrap();
        assert_eq!(updated.seq(), 2);
        assert_eq!(updated.endpoints().udp4, Some(30304));
        assert_eq!(updated.endpoints().ip4, Some(Ipv4Addr::LOCALHOST));
        assert_eq!(updated.node_id(), enr.node_id());
    }

    #[test]
    fn structural_rules() {
        let key = SecretKey::from_bytes(&[5; 32]).unwrap();
        // Records past 300 bytes are refused at building.
        assert_eq!(
            Enr::builder().bytes(b"big", &[0; 260]).build(&key),
            Err(EnrError::TooLarge { len: 387 })
        );
        // Keys out of order: "z" before "id".
        let mut encoder = Encoder::new();
        encoder.list(|list| {
            list.bytes(&[1; 64]).uint(1);
            list.bytes(b"z").bytes(b"").bytes(b"id").bytes(b"v4");
        });
        assert_eq!(Enr::decode(&encoder.finish()), Err(EnrError::UnsortedKeys));
        // No scheme at all.
        let mut encoder = Encoder::new();
        encoder.list(|list| {
            list.bytes(&[1; 64]).uint(1);
        });
        assert_eq!(Enr::decode(&encoder.finish()), Err(EnrError::MissingScheme));
        // A non-canonical sequence number, 0x00.
        let mut encoder = Encoder::new();
        encoder.list(|list| {
            list.bytes(&[1; 64]).raw(&[0x00]);
        });
        assert_eq!(
            Enr::decode(&encoder.finish()),
            Err(EnrError::Rlp(RlpError::LeadingZeroInInteger))
        );
        // Text without the prefix.
        assert_eq!("abc".parse::<Enr>(), Err(EnrError::MissingPrefix));
    }

    #[test]
    fn node_id_matches_the_key() {
        // The record's identifier is keccak256 of the signer's uncompressed key.
        let key = SecretKey::from_bytes(&[9; 32]).unwrap();
        let enr = Enr::builder().build(&key).unwrap();
        assert_eq!(enr.node_id(), NodeId::from_public_key(&key.public_key()));
    }

    proptest! {
        #[test]
        fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..320)) {
            // Arbitrary bytes yield a record or an error.
            let _ = Enr::decode(&bytes);
        }

        #[test]
        fn mutated_records_never_panic(index in 0_usize..136, value in any::<u8>()) {
            // Mutation: overwrite one byte of a valid record.
            let mut bytes = Base64Url::decode(&EIP778_TEXT[4..]).unwrap();
            let index = index % bytes.len();
            bytes[index] = value;
            if let Ok(enr) = Enr::decode(&bytes) {
                // Whatever survives re-encodes to itself.
                prop_assert_eq!(enr.as_bytes(), &bytes[..]);
            }
        }
    }
}
