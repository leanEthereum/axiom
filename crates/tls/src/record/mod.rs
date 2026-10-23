//! The TLS record layer: framing a byte stream into typed, length-prefixed records.
//!
//! # Overview
//!
//! Every record opens with a five-byte header, per RFC 8446, section 5.1.
//!
//! ```text
//! [ type: u8 ][ legacy_record_version: u16 ][ length: u16 ][ fragment ]
//! ```
//!
//! A plaintext fragment holds at most 2^14 bytes.
//! Protection adds at most 256 bytes in TLS 1.3 and 2048 in TLS 1.2.

mod protection;

pub(crate) use protection::Protection;

use crate::ProtocolError;

/// The record version field after the first ClientHello.
pub(crate) const LEGACY_RECORD_VERSION: u16 = 0x0303;

/// The record version of the first ClientHello, which some middleboxes require.
///
/// RFC 8446, section 5.1: a client may send 0x0301 in the record carrying its first ClientHello.
pub(crate) const INITIAL_RECORD_VERSION: u16 = 0x0301;

/// Bytes of a record header.
pub(crate) const HEADER_LEN: usize = 5;

/// Most plaintext bytes in one record, per RFC 8446, section 5.1.
pub(crate) const MAX_PLAINTEXT: usize = 1 << 14;

/// Most bytes a protected record may add, per RFC 5246, section 6.2.3.
///
/// TLS 1.3 allows 256, per RFC 8446, section 5.2; the reader takes the larger TLS 1.2 bound.
const MAX_EXPANSION: usize = 2048;

/// A record content type, per RFC 8446, section 5.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ContentType(pub(crate) u8);

impl ContentType {
    /// change_cipher_spec.
    pub(crate) const CHANGE_CIPHER_SPEC: Self = Self(20);
    /// alert.
    pub(crate) const ALERT: Self = Self(21);
    /// handshake.
    pub(crate) const HANDSHAKE: Self = Self(22);
    /// application_data.
    pub(crate) const APPLICATION_DATA: Self = Self(23);
}

/// One record cut from the stream: its header and still-protected fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawRecord {
    /// The five-byte header, which TLS 1.3 authenticates.
    pub(crate) header: [u8; HEADER_LEN],
    /// The fragment.
    pub(crate) fragment: Vec<u8>,
}

impl RawRecord {
    /// Cuts the next whole record from the front of a buffer, or nothing until more bytes arrive.
    ///
    /// The version field is not checked beyond its first byte, per RFC 8446, section 5.1.
    pub(crate) fn take(buffer: &mut Vec<u8>) -> Result<Option<Self>, ProtocolError> {
        let Some(header) = buffer.first_chunk::<HEADER_LEN>().copied() else {
            return Ok(None);
        };
        let kind = header[0];
        if !(ContentType::CHANGE_CIPHER_SPEC.0..=ContentType::APPLICATION_DATA.0).contains(&kind) {
            return Err(ProtocolError::UnexpectedRecord(kind));
        }
        // Every version of TLS writes 0x03 first.
        if header[1] != 0x03 {
            return Err(ProtocolError::InvalidRecordVersion(u16::from_be_bytes([
                header[1], header[2],
            ])));
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let max = MAX_PLAINTEXT + MAX_EXPANSION;
        if length > max {
            return Err(ProtocolError::RecordOverflow { length, max });
        }
        if buffer.len() < HEADER_LEN + length {
            return Ok(None);
        }
        let fragment = buffer[HEADER_LEN..HEADER_LEN + length].to_vec();
        buffer.drain(..HEADER_LEN + length);
        Ok(Some(Self { header, fragment }))
    }

    /// A plaintext record of a type with a version.
    pub(crate) fn plaintext(kind: ContentType, version: u16, fragment: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(HEADER_LEN + fragment.len());
        record.push(kind.0);
        record.extend_from_slice(&version.to_be_bytes());
        record.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        record.extend_from_slice(fragment);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_cut_whole() {
        // A handshake record of 3 bytes, split across two arrivals, then the start of another.
        let mut buffer = vec![22, 3, 3, 0, 3, 1];
        assert_eq!(RawRecord::take(&mut buffer), Ok(None));
        buffer.extend_from_slice(&[2, 3, 23]);
        assert_eq!(
            RawRecord::take(&mut buffer),
            Ok(Some(RawRecord {
                header: [22, 3, 3, 0, 3],
                fragment: vec![1, 2, 3],
            }))
        );
        assert_eq!(buffer, [23]);
    }

    #[test]
    fn malformed_headers_are_refused() {
        // Mutation: content type 24, an SSL 2 version byte, and a length past the bound.
        assert_eq!(
            RawRecord::take(&mut vec![24, 3, 3, 0, 0]),
            Err(ProtocolError::UnexpectedRecord(24))
        );
        assert_eq!(
            RawRecord::take(&mut vec![22, 2, 0, 0, 0]),
            Err(ProtocolError::InvalidRecordVersion(0x0200))
        );
        assert_eq!(
            RawRecord::take(&mut vec![23, 3, 3, 0x48, 0x01]),
            Err(ProtocolError::RecordOverflow {
                length: 0x4801,
                max: 18_432
            })
        );
    }
}
