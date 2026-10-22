//! Identify: peers describe themselves once a connection is up.
//!
//! # Overview
//!
//! The dialer of an identify stream only listens.
//! The listener writes one length-prefixed message, then closes the stream.
//!
//! ```text
//! message Identify {
//!   optional bytes publicKey = 1;
//!   repeated bytes listenAddrs = 2;     binary multiaddresses
//!   repeated string protocols = 3;
//!   optional bytes observedAddr = 4;    the dialer's address as seen by the listener
//!   optional string protocolVersion = 5;
//!   optional string agentVersion = 6;
//!   optional bytes signedPeerRecord = 8;
//! }
//! ```
//!
//! See `libp2p/specs/identify/README.md`.

use crate::{
    identity::PublicKey,
    multiaddr::Multiaddr,
    protobuf::{FieldReader, ProtoMessage, ProtobufError, encode_bytes_field},
};

/// The multistream-select name.
pub const PROTOCOL: &str = "/ipfs/id/1.0.0";

/// Longest identify message accepted.
///
/// Implementations cap it at a few KiB; a node lists tens of protocols at most.
pub const MAX_MESSAGE_LEN: usize = 8 * 1024;

/// Most listen addresses kept from one message.
const MAX_ADDRESSES: usize = 32;

/// Most protocols kept from one message.
const MAX_PROTOCOLS: usize = 128;

/// What a peer says about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentifyInfo {
    /// The family of protocols the peer speaks, such as `ipfs/0.1.0`.
    pub protocol_version: String,
    /// The software and version of the peer.
    pub agent_version: String,
    /// The peer's identity key.
    pub public_key: PublicKey,
    /// Addresses the peer listens on.
    pub listen_addrs: Vec<Multiaddr>,
    /// The address the peer sees this node at, useful to learn a public address.
    pub observed_addr: Option<Multiaddr>,
    /// Protocols the peer supports.
    pub protocols: Vec<String>,
}

impl ProtoMessage for IdentifyInfo {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_bytes_field(1, &self.public_key.encode(), out);
        for addr in &self.listen_addrs {
            encode_bytes_field(2, &addr.to_bytes(), out);
        }
        for protocol in &self.protocols {
            encode_bytes_field(3, protocol.as_bytes(), out);
        }
        if let Some(addr) = &self.observed_addr {
            encode_bytes_field(4, &addr.to_bytes(), out);
        }
        encode_bytes_field(5, self.protocol_version.as_bytes(), out);
        encode_bytes_field(6, self.agent_version.as_bytes(), out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
        let mut public_key = None;
        let mut listen_addrs = Vec::new();
        let mut protocols = Vec::new();
        let mut observed_addr = None;
        let mut protocol_version = String::new();
        let mut agent_version = String::new();
        let mut reader = FieldReader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match field.number {
                1 => public_key = Some(PublicKey::decode(field.bytes()?)?),
                // An address with an unsupported protocol, such as dns, is skipped, not fatal.
                2 => {
                    if let Ok(addr) = Multiaddr::from_bytes(field.bytes()?)
                        && listen_addrs.len() < MAX_ADDRESSES
                    {
                        listen_addrs.push(addr);
                    }
                }
                3 => {
                    if protocols.len() == MAX_PROTOCOLS {
                        return Err(ProtobufError::TooManyElements {
                            field: 3,
                            max: MAX_PROTOCOLS,
                        });
                    }
                    protocols.push(field.string()?.to_owned());
                }
                4 => observed_addr = Multiaddr::from_bytes(field.bytes()?).ok(),
                5 => field.string()?.clone_into(&mut protocol_version),
                6 => field.string()?.clone_into(&mut agent_version),
                // The signed peer record (8) is not used by consensus nodes.
                _ => {}
            }
        }
        Ok(Self {
            protocol_version,
            agent_version,
            // Without a key, nothing ties the message to the peer.
            public_key: public_key.ok_or(ProtobufError::MissingField(1))?,
            listen_addrs,
            observed_addr,
            protocols,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn layout_and_round_trip() {
        let info = IdentifyInfo {
            protocol_version: "eth2/1.0.0".into(),
            agent_version: "axiom/0.1.0".into(),
            public_key: PublicKey::secp256k1([2; 33]),
            listen_addrs: vec!["/ip4/1.2.3.4/tcp/9000".parse().unwrap()],
            observed_addr: Some("/ip4/5.6.7.8/tcp/40000".parse().unwrap()),
            protocols: vec!["/meshsub/1.2.0".into()],
        };
        let bytes = info.encode();
        // Field 1 (key 0x0a) wraps the 37-byte key envelope.
        assert_eq!(&bytes[..2], &[0x0a, 37]);
        // Field 2 (key 0x12) wraps the 8-byte binary address.
        assert_eq!(&bytes[39..41], &[0x12, 8]);
        assert_eq!(IdentifyInfo::decode(&bytes), Ok(info));
    }

    #[test]
    fn skips_unsupported_addresses() {
        // A dns4 address (code 0x36) is dropped; the message still decodes.
        let mut bytes = Vec::new();
        encode_bytes_field(1, &PublicKey::secp256k1([2; 33]).encode(), &mut bytes);
        encode_bytes_field(2, &[0x36, 0x01, b'a'], &mut bytes);
        let info = IdentifyInfo::decode(&bytes).unwrap();
        assert_eq!(info.listen_addrs, Vec::<Multiaddr>::new());
    }

    proptest! {
        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = IdentifyInfo::decode(&bytes);
        }

        #[test]
        fn round_trip(agent in "[ -~]{0,32}", protocols in proptest::collection::vec("/[a-z0-9/.]{1,20}", 0..8), port: u16) {
            let info = IdentifyInfo {
                protocol_version: "ipfs/0.1.0".into(),
                agent_version: agent,
                public_key: PublicKey::secp256k1([3; 33]),
                listen_addrs: vec![Multiaddr::from_tcp(([10, 0, 0, 1], port).into())],
                observed_addr: None,
                protocols,
            };
            prop_assert_eq!(IdentifyInfo::decode(&info.encode()), Ok(info));
        }
    }
}
