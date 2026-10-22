//! The kind-specific part of a packet header.

use axiom_crypto::secp256k1::PublicKey;

use super::{IdNonce, PacketError};
use crate::{enr::Enr, node_id::NodeId};

/// Flag of an ordinary message packet.
pub(crate) const FLAG_MESSAGE: u8 = 0;

/// Flag of a WHOAREYOU packet.
pub(crate) const FLAG_WHOAREYOU: u8 = 1;

/// Flag of a handshake message packet.
pub(crate) const FLAG_HANDSHAKE: u8 = 2;

/// Signature size of the "v4" scheme: r || s.
const V4_SIGNATURE_LEN: u8 = 64;

/// Ephemeral key size of the "v4" scheme: a compressed point.
const V4_KEY_LEN: u8 = 33;

/// Fixed head of handshake authdata: source id, then the two sizes.
const HANDSHAKE_HEAD_LEN: usize = 34;

/// The authdata of a packet, one shape per packet kind.
///
/// See discv5-wire.md, "Packet Encoding".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthData {
    /// An ordinary message packet names its sender.
    Message {
        /// The sender's node id.
        src_id: NodeId,
    },

    /// A WHOAREYOU challenge.
    WhoAreYou {
        /// The value the peer must sign over.
        id_nonce: IdNonce,
        /// The sequence number of the peer's record held by the challenger, zero for none.
        enr_seq: u64,
    },

    /// A handshake message packet answers a challenge and opens a session.
    Handshake {
        /// The sender's node id.
        src_id: NodeId,
        /// The sender's signature over the challenge, "v4" scheme.
        id_signature: [u8; 64],
        /// The sender's ephemeral key for this session.
        ephemeral_key: PublicKey,
        /// The sender's record, when the challenger's copy is stale.
        record: Option<Box<Enr>>,
    },
}

impl AuthData {
    /// The flag that tells the packet kind.
    #[must_use]
    pub const fn flag(&self) -> u8 {
        match self {
            Self::Message { .. } => FLAG_MESSAGE,
            Self::WhoAreYou { .. } => FLAG_WHOAREYOU,
            Self::Handshake { .. } => FLAG_HANDSHAKE,
        }
    }

    /// Appends the encoding.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            // The source id alone, 32 bytes.
            Self::Message { src_id } => out.extend_from_slice(&src_id.0),
            // The id-nonce, then the sequence number as 8 big-endian bytes.
            Self::WhoAreYou { id_nonce, enr_seq } => {
                out.extend_from_slice(&id_nonce.0);
                out.extend_from_slice(&enr_seq.to_be_bytes());
            }
            // Head, signature, key, then the optional record.
            Self::Handshake {
                src_id,
                id_signature,
                ephemeral_key,
                record,
            } => {
                out.extend_from_slice(&src_id.0);
                out.push(V4_SIGNATURE_LEN);
                out.push(V4_KEY_LEN);
                out.extend_from_slice(id_signature);
                out.extend_from_slice(&ephemeral_key.to_compressed());
                if let Some(record) = record {
                    out.extend_from_slice(record.as_bytes());
                }
            }
        }
    }

    /// Decodes the authdata of a packet of the given flag.
    ///
    /// # Errors
    ///
    /// Fails when the size does not fit the kind, on a non-"v4" handshake,
    /// and on an invalid ephemeral key or record.
    pub fn decode(flag: u8, bytes: &[u8]) -> Result<Self, PacketError> {
        // Sizes are checked against the kind before any field is read.
        let size_error = PacketError::AuthDataSize {
            flag,
            size: u16::try_from(bytes.len()).unwrap_or(u16::MAX),
        };
        match flag {
            FLAG_MESSAGE => {
                let src_id = bytes.try_into().map_err(|_| size_error)?;
                Ok(Self::Message {
                    src_id: NodeId(src_id),
                })
            }
            FLAG_WHOAREYOU => {
                let bytes: &[u8; 24] = bytes.try_into().map_err(|_| size_error)?;
                let (id_nonce, enr_seq) = bytes.split_at(16);
                Ok(Self::WhoAreYou {
                    // Invariant: the split leaves exactly 16 and 8 bytes.
                    id_nonce: IdNonce(id_nonce.try_into().expect("16 bytes")),
                    enr_seq: u64::from_be_bytes(enr_seq.try_into().expect("8 bytes")),
                })
            }
            FLAG_HANDSHAKE => Self::decode_handshake(bytes, size_error),
            other => Err(PacketError::Flag(other)),
        }
    }

    /// Decodes handshake authdata.
    fn decode_handshake(bytes: &[u8], size_error: PacketError) -> Result<Self, PacketError> {
        // Phase 1: the fixed head, and the "v4" sizes it must name.
        let Some((head, rest)) = bytes.split_first_chunk::<HANDSHAKE_HEAD_LEN>() else {
            return Err(size_error);
        };
        let (src_id, sizes) = head.split_at(32);
        if sizes[0] != V4_SIGNATURE_LEN {
            return Err(PacketError::SignatureSize(sizes[0]));
        }
        if sizes[1] != V4_KEY_LEN {
            return Err(PacketError::EphemeralKeySize(sizes[1]));
        }

        // Phase 2: signature and key, then whatever remains is the record.
        let Some((id_signature, rest)) = rest.split_first_chunk::<64>() else {
            return Err(size_error);
        };
        let Some((ephemeral_key, record)) = rest.split_first_chunk::<33>() else {
            return Err(size_error);
        };
        let ephemeral_key =
            PublicKey::from_compressed(ephemeral_key).map_err(PacketError::EphemeralKey)?;
        let record = match record {
            [] => None,
            bytes => Some(Box::new(Enr::decode(bytes).map_err(PacketError::Record)?)),
        };
        Ok(Self::Handshake {
            // Invariant: the head split leaves exactly 32 bytes of id.
            src_id: NodeId(src_id.try_into().expect("32 bytes")),
            id_signature: *id_signature,
            ephemeral_key,
            record,
        })
    }
}
