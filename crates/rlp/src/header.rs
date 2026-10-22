//! The prefix that opens every RLP item: its kind and its payload length.

use crate::RlpError;

/// First prefix of a short string, whose payload is under 56 bytes.
const SHORT_STRING: u8 = 0x80;

/// First prefix of a long string, whose length follows in big-endian bytes.
const LONG_STRING: u8 = 0xb8;

/// First prefix of a short list.
const SHORT_LIST: u8 = 0xc0;

/// First prefix of a long list.
const LONG_LIST: u8 = 0xf8;

/// Longest payload the short form can carry.
///
/// The short form spends 56 prefix values on lengths 0 to 55, per the Yellow Paper, appendix B.
const SHORT_LIMIT: usize = 55;

/// Whether an item is a byte string or a list of items.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A byte string.
    String,

    /// A list of items.
    List,
}

/// The decoded prefix of one item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Header {
    /// Whether the payload is a string or a list.
    pub kind: Kind,
    /// Bytes in the payload.
    pub payload_len: usize,
}

impl Header {
    /// A string header for a payload of a given length.
    #[must_use]
    pub const fn string(payload_len: usize) -> Self {
        Self {
            kind: Kind::String,
            payload_len,
        }
    }

    /// A list header for a payload of a given length.
    #[must_use]
    pub const fn list(payload_len: usize) -> Self {
        Self {
            kind: Kind::List,
            payload_len,
        }
    }

    /// Bytes this header occupies on the wire.
    ///
    /// A lone byte below `0x80` has no header, which only the encoder of strings knows.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        // Short form: the prefix byte alone.
        if self.payload_len <= SHORT_LIMIT {
            return 1;
        }
        // Long form: the prefix byte, then the length in minimal big-endian bytes.
        1 + Self::length_bytes(self.payload_len)
    }

    /// Appends this header to a buffer.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        // The two prefix ranges differ only in their base values.
        let (short_base, long_base) = match self.kind {
            Kind::String => (SHORT_STRING, LONG_STRING),
            Kind::List => (SHORT_LIST, LONG_LIST),
        };
        if self.payload_len <= SHORT_LIMIT {
            // Invariant: the length is at most 55, so the cast is exact.
            out.push(short_base + self.payload_len as u8);
            return;
        }
        // Long form: the prefix encodes how many length bytes follow.
        let width = Self::length_bytes(self.payload_len);
        // Invariant: a usize has at most 8 bytes, so the width fits the 8 long-form prefixes.
        out.push(long_base + (width as u8) - 1);
        let bytes = self.payload_len.to_be_bytes();
        out.extend_from_slice(&bytes[bytes.len() - width..]);
    }

    /// Decodes the header at the start of the input.
    ///
    /// # Returns
    ///
    /// The header and the offset of its payload.
    /// A lone byte below `0x80` is its own payload, at offset zero.
    ///
    /// # Errors
    ///
    /// Fails on any non-canonical form, and when the payload runs past the input.
    pub fn decode(input: &[u8]) -> Result<(Self, usize), RlpError> {
        let Some(&prefix) = input.first() else {
            return Err(RlpError::UnexpectedEnd);
        };
        let (header, offset) = match prefix {
            // A byte below 0x80 is a one-byte string encoded as itself.
            0x00..SHORT_STRING => (Self::string(1), 0),
            SHORT_STRING..LONG_STRING => {
                let header = Self::string(usize::from(prefix - SHORT_STRING));
                // Canonical: a lone byte below 0x80 never takes a header.
                if header.payload_len == 1 && input.get(1).is_some_and(|&byte| byte < SHORT_STRING)
                {
                    return Err(RlpError::NonCanonicalSingleByte);
                }
                (header, 1)
            }
            LONG_STRING..SHORT_LIST => {
                let width = usize::from(prefix - LONG_STRING) + 1;
                (Self::string(Self::long_length(input, width)?), 1 + width)
            }
            SHORT_LIST..LONG_LIST => (Self::list(usize::from(prefix - SHORT_LIST)), 1),
            LONG_LIST..=u8::MAX => {
                let width = usize::from(prefix - LONG_LIST) + 1;
                (Self::list(Self::long_length(input, width)?), 1 + width)
            }
        };
        // The payload must lie inside the input.
        let end = offset
            .checked_add(header.payload_len)
            .ok_or(RlpError::LengthOverflow)?;
        if end > input.len() {
            return Err(RlpError::UnexpectedEnd);
        }
        Ok((header, offset))
    }

    /// Reads a long-form length of a given byte width, right after the prefix.
    fn long_length(input: &[u8], width: usize) -> Result<usize, RlpError> {
        let bytes = input.get(1..1 + width).ok_or(RlpError::UnexpectedEnd)?;
        // Canonical: the length is minimal, so it never opens with zero.
        if bytes[0] == 0 {
            return Err(RlpError::LeadingZeroInLength);
        }
        // Accumulate big-endian, refusing anything the address space cannot hold.
        let mut length: usize = 0;
        for &byte in bytes {
            length = length
                .checked_mul(256)
                .and_then(|shifted| shifted.checked_add(usize::from(byte)))
                .ok_or(RlpError::LengthOverflow)?;
        }
        // Canonical: the long form starts where the short form ends.
        if length <= SHORT_LIMIT {
            return Err(RlpError::NonCanonicalLength);
        }
        Ok(length)
    }

    /// Bytes in the minimal big-endian form of a positive length.
    const fn length_bytes(length: usize) -> usize {
        // Count significant bytes: total width minus whole leading zero bytes.
        size_of::<usize>() - (length.leading_zeros() as usize / 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_long_forms_meet_at_fifty_six() {
        // 55 bytes fit the short form: one prefix byte, 0x80 + 55 = 0xb7.
        let mut out = Vec::new();
        Header::string(55).encode_to(&mut out);
        assert_eq!(out, [0xb7]);
        // 56 bytes need the long form: 0xb8 says one length byte follows.
        out.clear();
        Header::string(56).encode_to(&mut out);
        assert_eq!(out, [0xb8, 56]);
        // A 1024-byte list takes two length bytes, 0x04 0x00.
        out.clear();
        Header::list(1024).encode_to(&mut out);
        assert_eq!(out, [0xf9, 0x04, 0x00]);
        assert_eq!(Header::list(1024).encoded_len(), 3);
    }

    #[test]
    fn decode_reports_the_payload_offset() {
        // 0x05 is a one-byte string at offset zero.
        assert_eq!(Header::decode(&[0x05]), Ok((Header::string(1), 0)));
        // 0x82 opens a two-byte string at offset one.
        assert_eq!(
            Header::decode(&[0x82, 0xaa, 0xbb]),
            Ok((Header::string(2), 1))
        );
        // 0xc0 is the empty list.
        assert_eq!(Header::decode(&[0xc0]), Ok((Header::list(0), 1)));
    }

    #[test]
    fn decode_refuses_every_non_canonical_form() {
        // 0x81 0x7f wraps a byte that must stand alone.
        assert_eq!(
            Header::decode(&[0x81, 0x7f]),
            Err(RlpError::NonCanonicalSingleByte)
        );
        // 0xb8 0x02 uses the long form for two bytes.
        assert_eq!(
            Header::decode(&[0xb8, 0x02, 0, 0]),
            Err(RlpError::NonCanonicalLength)
        );
        // 0xb9 0x00 0x40 pads its length with a zero byte.
        assert_eq!(
            Header::decode(&[0xb9, 0x00, 0x40]),
            Err(RlpError::LeadingZeroInLength)
        );
        // 0x83 promises three bytes but only one follows.
        assert_eq!(Header::decode(&[0x83, 0x01]), Err(RlpError::UnexpectedEnd));
        // Eight length bytes declare 2^56 bytes, far past the input.
        assert_eq!(
            Header::decode(&[0xff, 1, 0, 0, 0, 0, 0, 0, 0]),
            Err(RlpError::UnexpectedEnd)
        );
        // A length of 2^64 - 1 plus a nine-byte header overflows the address space.
        assert_eq!(
            Header::decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(RlpError::LengthOverflow)
        );
        // An empty input has no header at all.
        assert_eq!(Header::decode(&[]), Err(RlpError::UnexpectedEnd));
    }
}
