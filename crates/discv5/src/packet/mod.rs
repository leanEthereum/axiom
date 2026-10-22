//! discv5 v5.1 packets: the masked header and the sealed message behind it.
//!
//! See discv5-wire.md, "Packet Encoding".

mod auth_data;
mod error;
mod nonce;

pub use auth_data::AuthData;
pub use error::PacketError;
pub use nonce::{IdNonce, MaskingIv, Nonce};

use crate::node_id::NodeId;

/// The protocol identifier that opens every unmasked header.
const PROTOCOL_ID: &[u8; 6] = b"discv5";

/// The wire protocol version, v5.1.
const VERSION: u16 = 1;

/// Bytes in the static header: protocol id, version, flag, nonce, authdata size.
const STATIC_HEADER_LEN: usize = 6 + 2 + 1 + 12 + 2;

/// Bytes in the masking IV.
const IV_LEN: usize = 16;

/// Smallest valid packet: a WHOAREYOU, 16 + 23 + 24 bytes.
pub const MIN_PACKET_LEN: usize = 63;

/// Largest packet any node sends or accepts.
///
/// The IPv6 minimum MTU, so datagrams never fragment.
pub const MAX_PACKET_LEN: usize = 1280;

/// Bytes of an AES-GCM tag, the least a sealed message can hold.
const TAG_LEN: usize = 16;

/// The unmasked header: nonce and authdata, behind the fixed protocol fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The packet nonce.
    pub nonce: Nonce,
    /// The kind-specific authdata.
    pub auth: AuthData,
}

impl Header {
    /// The unmasked encoding: static header, then authdata.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        // Authdata first, so its size is known for the static header.
        let mut auth = Vec::new();
        self.auth.encode_to(&mut auth);
        let mut out = Vec::with_capacity(STATIC_HEADER_LEN + auth.len());
        out.extend_from_slice(PROTOCOL_ID);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.push(self.auth.flag());
        out.extend_from_slice(&self.nonce.0);
        // Invariant: authdata is at most 34 + 64 + 33 + 300 bytes, well under 2^16.
        out.extend_from_slice(&(auth.len() as u16).to_be_bytes());
        out.extend_from_slice(&auth);
        out
    }
}

/// One discv5 packet.
///
/// # Overview
///
/// ```text
/// packet        = masking-iv || masked-header || message
/// masked-header = aesctr_encrypt(dest-id[..16], masking-iv, header)
/// header        = "discv5" || 0x0001 || flag || nonce || authdata-size || authdata
/// ```
///
/// The message stays sealed here; sessions open it.
/// Its additional data is the masking IV followed by the unmasked header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// The masking IV.
    pub masking_iv: MaskingIv,
    /// The unmasked header.
    pub header: Header,
    /// The sealed message, empty in a WHOAREYOU.
    pub message: Vec<u8>,
}

impl Packet {
    /// The additional data of the sealed message: masking IV, then unmasked header.
    ///
    /// For a WHOAREYOU, these bytes are the challenge data of the handshake.
    #[must_use]
    pub fn message_ad(&self) -> Vec<u8> {
        // The header re-encodes to its wire bytes, since every field has one encoding.
        let mut ad = self.masking_iv.0.to_vec();
        ad.extend_from_slice(&self.header.encode());
        ad
    }

    /// The datagram for a destination node.
    #[must_use]
    pub fn encode(&self, dest: &NodeId) -> Vec<u8> {
        // Mask the header under the destination's id, then append the message.
        let mut header = self.header.encode();
        self.masking_iv.cipher(dest).apply_keystream(&mut header);
        let mut out = Vec::with_capacity(IV_LEN + header.len() + self.message.len());
        out.extend_from_slice(&self.masking_iv.0);
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.message);
        out
    }

    /// Unmasks and parses a datagram addressed to the local node.
    ///
    /// # Errors
    ///
    /// Fails outside 63 to 1280 bytes, when the header does not unmask to discv5 v1,
    /// and when the authdata or message does not fit the packet kind.
    pub fn decode(local: &NodeId, datagram: &[u8]) -> Result<Self, PacketError> {
        // Threshold: the wire spec bounds every packet to 63..=1280 bytes.
        if datagram.len() < MIN_PACKET_LEN {
            return Err(PacketError::TooSmall {
                len: datagram.len(),
            });
        }
        if datagram.len() > MAX_PACKET_LEN {
            return Err(PacketError::TooLarge {
                len: datagram.len(),
            });
        }

        // Phase 1: unmask the static header and check the protocol fields.
        let Some((iv, rest)) = datagram.split_first_chunk::<IV_LEN>() else {
            return Err(PacketError::TooSmall {
                len: datagram.len(),
            });
        };
        let masking_iv = MaskingIv(*iv);
        let mut cipher = masking_iv.cipher(local);
        let mut fixed = [0_u8; STATIC_HEADER_LEN];
        fixed.copy_from_slice(&rest[..STATIC_HEADER_LEN]);
        cipher.apply_keystream(&mut fixed);
        if &fixed[..6] != PROTOCOL_ID {
            return Err(PacketError::ProtocolId);
        }
        let version = u16::from_be_bytes([fixed[6], fixed[7]]);
        if version != VERSION {
            return Err(PacketError::Version(version));
        }
        let flag = fixed[8];
        let mut nonce = [0_u8; 12];
        nonce.copy_from_slice(&fixed[9..21]);
        let size = u16::from_be_bytes([fixed[21], fixed[22]]);

        // Phase 2: unmask the authdata, continuing the same keystream.
        let rest = &rest[STATIC_HEADER_LEN..];
        let Some((auth, message)) = rest.split_at_checked(usize::from(size)) else {
            return Err(PacketError::AuthDataSize { flag, size });
        };
        let mut auth = auth.to_vec();
        cipher.apply_keystream(&mut auth);
        let auth = AuthData::decode(flag, &auth)?;

        // Phase 3: a challenge carries no message; other packets carry at least a tag.
        match auth {
            AuthData::WhoAreYou { .. } if !message.is_empty() => {
                return Err(PacketError::UnexpectedMessage { len: message.len() });
            }
            AuthData::Message { .. } | AuthData::Handshake { .. } if message.len() < TAG_LEN => {
                return Err(PacketError::MessageTooShort { len: message.len() });
            }
            _ => {}
        }
        Ok(Self {
            masking_iv,
            header: Header {
                nonce: Nonce(nonce),
                auth,
            },
            message: message.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::secp256k1::SecretKey;
    use proptest::prelude::*;

    use super::*;

    /// A WHOAREYOU with a zero IV and the given nonce byte.
    fn whoareyou(nonce: u8) -> Packet {
        Packet {
            masking_iv: MaskingIv([0; 16]),
            header: Header {
                nonce: Nonce([nonce; 12]),
                auth: AuthData::WhoAreYou {
                    id_nonce: IdNonce([7; 16]),
                    enr_seq: 3,
                },
            },
            message: Vec::new(),
        }
    }

    #[test]
    fn size_bounds() {
        // 62 bytes is one short of the smallest packet; 1281 one past the largest.
        let local = NodeId([0xbb; 32]);
        assert_eq!(
            Packet::decode(&local, &[0; 62]),
            Err(PacketError::TooSmall { len: 62 })
        );
        assert_eq!(
            Packet::decode(&local, &[0; 1281]),
            Err(PacketError::TooLarge { len: 1281 })
        );
    }

    #[test]
    fn masking_binds_the_destination() {
        // A WHOAREYOU is exactly 63 bytes and round-trips for its destination.
        let dest = NodeId([0xbb; 32]);
        let bytes = whoareyou(1).encode(&dest);
        assert_eq!(bytes.len(), MIN_PACKET_LEN);
        assert_eq!(Packet::decode(&dest, &bytes), Ok(whoareyou(1)));
        // Another node unmasks noise, so the protocol id fails.
        assert_eq!(
            Packet::decode(&NodeId([0xcc; 32]), &bytes),
            Err(PacketError::ProtocolId)
        );
    }

    #[test]
    fn kind_rules() {
        let dest = NodeId([0xbb; 32]);
        // Mutation: a WHOAREYOU with one trailing message byte.
        let mut bytes = whoareyou(1).encode(&dest);
        bytes.push(0);
        assert_eq!(
            Packet::decode(&dest, &bytes),
            Err(PacketError::UnexpectedMessage { len: 1 })
        );
        // A message packet whose message is 15 bytes, one short of a tag.
        let packet = Packet {
            masking_iv: MaskingIv([1; 16]),
            header: Header {
                nonce: Nonce([2; 12]),
                auth: AuthData::Message {
                    src_id: NodeId([3; 32]),
                },
            },
            message: vec![0; 15],
        };
        assert_eq!(
            Packet::decode(&dest, &packet.encode(&dest)),
            Err(PacketError::MessageTooShort { len: 15 })
        );
    }

    #[test]
    fn handshake_round_trips_without_record() {
        // 34 + 64 + 33 bytes of authdata, then a 16-byte sealed message.
        let dest = NodeId([0xbb; 32]);
        let ephemeral = SecretKey::from_bytes(&[4; 32]).unwrap().public_key();
        let packet = Packet {
            masking_iv: MaskingIv([5; 16]),
            header: Header {
                nonce: Nonce([6; 12]),
                auth: AuthData::Handshake {
                    src_id: NodeId([7; 32]),
                    id_signature: [8; 64],
                    ephemeral_key: ephemeral,
                    record: None,
                },
            },
            message: vec![9; 16],
        };
        let bytes = packet.encode(&dest);
        assert_eq!(bytes.len(), 16 + 23 + 131 + 16);
        assert_eq!(Packet::decode(&dest, &bytes), Ok(packet));
    }

    proptest! {
        #[test]
        fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..1400)) {
            // Arbitrary datagrams yield a packet or an error.
            let _ = Packet::decode(&NodeId([0xbb; 32]), &bytes);
        }

        #[test]
        fn decoded_packets_re_encode(
            iv in any::<[u8; 16]>(),
            flag in 0_u8..3,
            size in 0_u16..200,
            tail in prop::collection::vec(any::<u8>(), 0..300),
        ) {
            // Build a masked header with an arbitrary flag and size, so decoding reaches the authdata.
            let dest = NodeId([0xbb; 32]);
            let mut header = PROTOCOL_ID.to_vec();
            header.extend_from_slice(&VERSION.to_be_bytes());
            header.push(flag);
            header.extend_from_slice(&[0; 12]);
            header.extend_from_slice(&size.to_be_bytes());
            header.extend_from_slice(&tail);
            MaskingIv(iv).cipher(&dest).apply_keystream(&mut header);
            let mut bytes = iv.to_vec();
            bytes.extend_from_slice(&header);
            if let Ok(packet) = Packet::decode(&dest, &bytes) {
                // Whatever is accepted re-encodes to the same datagram.
                prop_assert_eq!(packet.encode(&dest), bytes);
            }
        }
    }
}
