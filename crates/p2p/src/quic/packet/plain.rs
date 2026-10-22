//! Outgoing packets before protection: a header, frames, and later the seal.
//!
//! A datagram's packets are assembled in the clear first and sealed together at the end.
//! That order lets the last packet absorb any padding the datagram needs.
//! See RFC 9000, section 14.1, for the 1200-byte rule on Initial datagrams.

use super::{FIXED_BIT, LONG_FORM, LongType, PacketNumber};
use crate::quic::{
    ConnectionId, DecodeError, VERSION, VarInt,
    crypto::{HeaderKey, TAG_LEN},
    space::Space,
};

/// A packet whose frames are written but which is not yet sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlainPacket {
    /// The packet number space.
    pub(crate) space: Space,
    /// The packet number.
    pub(crate) number: PacketNumber,
    /// The header up to and including the truncated packet number.
    header: Vec<u8>,
    /// Bytes of the truncated packet number.
    pn_len: usize,
    /// Where the two-byte Length field sits, for long headers.
    length_at: Option<usize>,
    /// The frames.
    pub(crate) payload: Vec<u8>,
}

impl PlainPacket {
    /// A long-header packet: Initial or Handshake.
    pub(crate) fn long(
        kind: LongType,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        token: &[u8],
        number: PacketNumber,
        largest_acked: Option<PacketNumber>,
    ) -> Self {
        Self::long_with_len(
            kind,
            dcid,
            scid,
            token,
            number,
            number.encoded_len(largest_acked),
        )
    }

    /// A long-header packet with a chosen packet number length.
    fn long_with_len(
        kind: LongType,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        token: &[u8],
        number: PacketNumber,
        pn_len: usize,
    ) -> Self {
        let mut header = Vec::with_capacity(64 + token.len());
        // Invariant: pn_len is 1 to 4, so pn_len - 1 fits the two low bits.
        header.push(LONG_FORM | FIXED_BIT | (kind.bits() << 4) | (pn_len as u8 - 1));
        header.extend_from_slice(&VERSION.to_be_bytes());
        dcid.encode_with_length(&mut header);
        scid.encode_with_length(&mut header);
        if kind == LongType::Initial {
            VarInt::saturating(token.len() as u64).encode(&mut header);
            header.extend_from_slice(token);
        }
        let length_at = header.len();
        header.extend_from_slice(&[0, 0]);
        let space = if kind == LongType::Initial {
            Space::Initial
        } else {
            Space::Handshake
        };
        Self::with_number(space, number, header, pn_len, Some(length_at))
    }

    /// A short-header packet.
    pub(crate) fn short(
        dcid: &ConnectionId,
        key_phase: bool,
        number: PacketNumber,
        largest_acked: Option<PacketNumber>,
    ) -> Self {
        let pn_len = number.encoded_len(largest_acked);
        let mut header = Vec::with_capacity(1 + dcid.len() + 4);
        header.push(FIXED_BIT | (u8::from(key_phase) << 2) | (pn_len as u8 - 1));
        header.extend_from_slice(dcid.as_bytes());
        Self::with_number(Space::Data, number, header, pn_len, None)
    }

    /// Appends the truncated number to a header.
    fn with_number(
        space: Space,
        number: PacketNumber,
        mut header: Vec<u8>,
        pn_len: usize,
        length_at: Option<usize>,
    ) -> Self {
        let truncated = number.truncate(pn_len).to_be_bytes();
        header.extend_from_slice(&truncated[4 - pn_len..]);
        Self {
            space,
            number,
            header,
            pn_len,
            length_at,
            payload: Vec::new(),
        }
    }

    /// Bytes the packet takes on the wire once sealed.
    pub(crate) const fn wire_len(&self) -> usize {
        self.header.len() + self.payload.len() + TAG_LEN
    }

    /// Bytes the packet takes on the wire with an empty payload.
    pub(crate) const fn overhead(&self) -> usize {
        self.header.len() + TAG_LEN
    }

    /// Pads the payload so header protection finds its 16-byte sample.
    ///
    /// The sample starts four bytes after the packet number, so number and payload need four bytes.
    pub(crate) fn pad_for_sample(&mut self) {
        let needed = 4_usize.saturating_sub(self.pn_len + self.payload.len());
        self.payload.resize(self.payload.len() + needed, 0);
    }

    /// Seals the packet into a datagram.
    ///
    /// # Arguments
    ///
    /// - `seal`: encrypts the payload in place under the header, returning the tag.
    /// - `header_key`: masks the header.
    /// - `out`: the datagram the packet is appended to.
    pub(crate) fn seal(
        mut self,
        seal: impl FnOnce(PacketNumber, &[u8], &mut [u8]) -> [u8; TAG_LEN],
        header_key: &HeaderKey,
        out: &mut Vec<u8>,
    ) -> Result<(), DecodeError> {
        self.pad_for_sample();
        if let Some(at) = self.length_at {
            let length = self.pn_len + self.payload.len() + TAG_LEN;
            let mut field = [0; 2];
            // Invariant: a datagram never exceeds 16383 bytes, the two-byte varint range.
            VarInt::saturating(length as u64).encode_two_bytes(&mut field);
            self.header[at..at + 2].copy_from_slice(&field);
        }
        let tag = seal(self.number, &self.header, &mut self.payload);
        let start = out.len();
        let pn_offset = start + self.header.len() - self.pn_len;
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&tag);
        header_key.protect(&mut out[start..], pn_offset - start, self.pn_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{
        crypto::InitialSecrets,
        testing::{RFC9001_CLIENT_CRYPTO_FRAME, RFC9001_CLIENT_INITIAL, hex},
    };

    #[test]
    fn rebuilds_the_rfc_9001_client_initial() {
        // Appendix A.2: dcid 8394c8f03e515708, empty scid and token, packet number 2 on four bytes.
        let dcid = ConnectionId::new(&hex("8394c8f03e515708")).unwrap();
        let mut packet = PlainPacket::long_with_len(
            LongType::Initial,
            &dcid,
            &ConnectionId::EMPTY,
            &[],
            PacketNumber(2),
            4,
        );
        packet.payload = hex(RFC9001_CLIENT_CRYPTO_FRAME);
        packet.payload.resize(1162, 0);
        let keys = InitialSecrets::new(&dcid).keys(true);
        let mut out = Vec::new();
        packet
            .seal(
                |number, header, payload| keys.local.packet.seal(number, header, payload),
                &keys.local.header,
                &mut out,
            )
            .unwrap();
        assert_eq!(out, hex(RFC9001_CLIENT_INITIAL));
    }

    #[test]
    fn short_header_and_sample_padding() {
        let dcid = ConnectionId::new(&[0xaa; 8]).unwrap();
        // Packet 7 after 5 was acknowledged: one byte; key phase set.
        let mut packet = PlainPacket::short(&dcid, true, PacketNumber(7), Some(PacketNumber(5)));
        assert_eq!(packet.header[0], 0x44);
        assert_eq!(packet.overhead(), 1 + 8 + 1 + 16);
        // A one-byte PING needs two padding bytes for the sample.
        packet.payload.push(0x01);
        packet.pad_for_sample();
        assert_eq!(packet.payload, [0x01, 0, 0]);
        assert_eq!(packet.wire_len(), 10 + 3 + 16);
    }
}
