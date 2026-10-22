//! A minimal protobuf wire codec, enough for every libp2p message.
//!
//! # Overview
//!
//! A protobuf message is a flat run of fields.
//! Each field opens with a key: the field number and a wire type, packed in one varint.
//!
//! ```text
//! key = (field_number << 3) | wire_type
//!
//! wire type 0   varint             [ key ][ varint ]
//! wire type 1   64-bit fixed       [ key ][ 8 bytes LE ]
//! wire type 2   length-delimited   [ key ][ varint length ][ bytes ]
//! wire type 5   32-bit fixed       [ key ][ 4 bytes LE ]
//!
//! example: field 2, bytes "hi"
//!   key    = (2 << 3) | 2 = 0x12
//!   wire   = [0x12, 0x02, b'h', b'i']
//! ```
//!
//! Strings, bytes, and nested messages all use wire type 2.
//! Repeated fields repeat the key once per element.
//! Groups, wire types 3 and 4, are deprecated and rejected.
//!
//! Types are written by hand per message, with no code generation.
//! See `protocolbuffers.dev/docs/encoding`.

use std::str;

use thiserror::Error;

use crate::varint::{self, VarintError};

/// A protobuf message with a hand-written wire encoding.
pub trait ProtoMessage: Sized {
    /// Appends the encoding of this message, without a length prefix.
    fn encode_to(&self, out: &mut Vec<u8>);

    /// Decodes a message spanning exactly the given bytes.
    ///
    /// Unknown fields are skipped, as protobuf requires for forward compatibility.
    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError>;

    /// The encoding of this message in a fresh buffer.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_to(&mut out);
        out
    }
}

/// How a field's value is laid out after its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireType {
    /// A varint.
    Varint,
    /// Eight little-endian bytes.
    Fixed64,
    /// A varint length, then that many bytes.
    LengthDelimited,
    /// Four little-endian bytes.
    Fixed32,
}

impl WireType {
    /// The three-bit tag of this wire type.
    #[must_use]
    pub const fn tag(self) -> u64 {
        match self {
            Self::Varint => 0,
            Self::Fixed64 => 1,
            Self::LengthDelimited => 2,
            Self::Fixed32 => 5,
        }
    }
}

/// The value of one decoded field, borrowed from the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldValue<'a> {
    /// A varint value.
    Varint(u64),
    /// A 64-bit fixed value.
    Fixed64(u64),
    /// A length-delimited value: bytes, a string, or a nested message.
    Bytes(&'a [u8]),
    /// A 32-bit fixed value.
    Fixed32(u32),
}

/// One field of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field<'a> {
    /// The field number from the schema.
    pub number: u32,
    /// The value that follows the key.
    pub value: FieldValue<'a>,
}

impl<'a> Field<'a> {
    /// The value as a varint, or an error naming this field.
    pub const fn varint(&self) -> Result<u64, ProtobufError> {
        match self.value {
            FieldValue::Varint(value) => Ok(value),
            _ => Err(ProtobufError::UnexpectedWireType(self.number)),
        }
    }

    /// The value as a boolean varint.
    pub const fn bool(&self) -> Result<bool, ProtobufError> {
        match self.varint() {
            Ok(value) => Ok(value != 0),
            Err(error) => Err(error),
        }
    }

    /// The value as length-delimited bytes.
    pub const fn bytes(&self) -> Result<&'a [u8], ProtobufError> {
        match self.value {
            FieldValue::Bytes(bytes) => Ok(bytes),
            _ => Err(ProtobufError::UnexpectedWireType(self.number)),
        }
    }

    /// The value as a UTF-8 string.
    pub fn string(&self) -> Result<&'a str, ProtobufError> {
        let bytes = self.bytes()?;
        str::from_utf8(bytes).map_err(|_| ProtobufError::InvalidUtf8(self.number))
    }
}

/// Walks the fields of one encoded message, in wire order.
#[derive(Clone, Debug)]
pub struct FieldReader<'a> {
    /// Bytes not yet consumed.
    rest: &'a [u8],
}

impl<'a> FieldReader<'a> {
    /// A reader over the encoding of one message.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// The next field, or nothing at the end of the message.
    pub fn next_field(&mut self) -> Result<Option<Field<'a>>, ProtobufError> {
        // An empty remainder ends the message cleanly.
        if self.rest.is_empty() {
            return Ok(None);
        }
        // Phase 1: the key packs the field number above three wire-type bits.
        let key = self.read_varint()?;
        let number = key >> 3;
        // Field numbers run from 1 to 2^29 - 1.
        if number == 0 || number > (1 << 29) - 1 {
            return Err(ProtobufError::InvalidFieldNumber);
        }
        // Invariant: number < 2^29, so it fits in a u32.
        let number = number as u32;
        // Phase 2: the wire type fixes how many bytes the value spans.
        let value = match key & 0x7 {
            0 => FieldValue::Varint(self.read_varint()?),
            1 => FieldValue::Fixed64(u64::from_le_bytes(self.read_array()?)),
            2 => {
                let len = self.read_varint()?;
                // A length past the end of input is a truncated message.
                let len = usize::try_from(len).map_err(|_| ProtobufError::Truncated)?;
                if len > self.rest.len() {
                    return Err(ProtobufError::Truncated);
                }
                let (bytes, rest) = self.rest.split_at(len);
                self.rest = rest;
                FieldValue::Bytes(bytes)
            }
            5 => FieldValue::Fixed32(u32::from_le_bytes(self.read_array()?)),
            // Groups (3, 4) and the unassigned tags (6, 7).
            other => return Err(ProtobufError::InvalidWireType(other as u8)),
        };
        Ok(Some(Field { number, value }))
    }

    /// Consumes one varint.
    fn read_varint(&mut self) -> Result<u64, ProtobufError> {
        // Inside a complete message, a varint cut short is truncation.
        let (value, len) = varint::decode(self.rest)?.ok_or(ProtobufError::Truncated)?;
        self.rest = &self.rest[len..];
        Ok(value)
    }

    /// Consumes a fixed-size little-endian value.
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ProtobufError> {
        let (head, rest) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(ProtobufError::Truncated)?;
        self.rest = rest;
        Ok(*head)
    }
}

/// Appends a field key.
fn encode_key(number: u32, wire_type: WireType, out: &mut Vec<u8>) {
    varint::encode((u64::from(number) << 3) | wire_type.tag(), out);
}

/// Appends a varint field.
pub fn encode_varint_field(number: u32, value: u64, out: &mut Vec<u8>) {
    encode_key(number, WireType::Varint, out);
    varint::encode(value, out);
}

/// Appends a length-delimited field holding raw bytes, a string, or a message.
pub fn encode_bytes_field(number: u32, bytes: &[u8], out: &mut Vec<u8>) {
    encode_key(number, WireType::LengthDelimited, out);
    varint::encode(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// Appends a nested message as a length-delimited field.
pub fn encode_message_field<M: ProtoMessage>(number: u32, message: &M, out: &mut Vec<u8>) {
    // The length prefix needs the nested size first, so encode into a scratch buffer.
    let nested = message.encode();
    encode_bytes_field(number, &nested, out);
}

/// Appends a message behind a varint length prefix, the framing libp2p streams use.
pub fn encode_length_prefixed<M: ProtoMessage>(message: &M, out: &mut Vec<u8>) {
    let body = message.encode();
    varint::encode(body.len() as u64, out);
    out.extend_from_slice(&body);
}

/// Splits one length-prefixed frame off the front of a buffer.
///
/// # Returns
///
/// - The frame body and the total bytes it took, prefix included.
/// - Nothing when the buffer does not yet hold the whole frame.
///
/// # Errors
///
/// Fails on a malformed prefix or a declared length above the bound.
/// The bound is checked before waiting for the body, so a peer cannot make the reader buffer it.
pub fn split_length_prefixed(
    buffer: &[u8],
    max_len: usize,
) -> Result<Option<(&[u8], usize)>, ProtobufError> {
    // The prefix follows the multiformats rules: at most nine bytes, minimal.
    let Some((len, prefix)) = varint::decode_multiformat(buffer)? else {
        return Ok(None);
    };
    // Reject an oversized frame as soon as its header arrives.
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    if len > max_len {
        return Err(ProtobufError::FrameTooLarge { len, max: max_len });
    }
    // Wait until the whole body is buffered.
    let end = prefix + len;
    if buffer.len() < end {
        return Ok(None);
    }
    Ok(Some((&buffer[prefix..end], end)))
}

/// A byte string that is not the encoding of the expected message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProtobufError {
    /// A key, length, or value varint is malformed.
    #[error("malformed varint: {0}")]
    Varint(VarintError),

    /// The input ends inside a field.
    #[error("message ends inside a field")]
    Truncated,

    /// A key uses a group or unassigned wire type.
    #[error("unsupported wire type {0}")]
    InvalidWireType(u8),

    /// A key carries field number zero or one above 2^29 - 1.
    #[error("field number out of range")]
    InvalidFieldNumber,

    /// A known field arrives with a wire type its schema forbids.
    #[error("field {0} has the wrong wire type")]
    UnexpectedWireType(u32),

    /// A required field is absent.
    #[error("required field {0} is missing")]
    MissingField(u32),

    /// A string field holds bytes that are not UTF-8.
    #[error("field {0} is not valid UTF-8")]
    InvalidUtf8(u32),

    /// An enum field holds a value outside the schema.
    #[error("field {field} holds unknown enum value {value}")]
    InvalidEnum {
        /// Field number.
        field: u32,
        /// The value found.
        value: u64,
    },

    /// A length-prefixed frame declares more bytes than the reader accepts.
    #[error("frame of {len} bytes exceeds the limit of {max}")]
    FrameTooLarge {
        /// Declared length.
        len: usize,
        /// Largest length accepted.
        max: usize,
    },

    /// A repeated field holds more elements than the reader accepts.
    #[error("field {field} repeats more than {max} times")]
    TooManyElements {
        /// Field number.
        field: u32,
        /// Largest count accepted.
        max: usize,
    },
}

impl From<VarintError> for ProtobufError {
    fn from(error: VarintError) -> Self {
        Self::Varint(error)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn field_layouts() {
        // Field 1, varint 150: the canonical example of the protobuf docs.
        //
        //     key   = (1 << 3) | 0 = 0x08
        //     150   = [0x96, 0x01]
        let mut out = Vec::new();
        encode_varint_field(1, 150, &mut out);
        assert_eq!(out, [0x08, 0x96, 0x01]);

        // Field 2, string "testing": key 0x12, length 7, then the bytes.
        let mut out = Vec::new();
        encode_bytes_field(2, b"testing", &mut out);
        assert_eq!(out, [0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g']);

        // Read both back in one message.
        let mut message = vec![0x08, 0x96, 0x01];
        message.extend_from_slice(&out);
        let mut reader = FieldReader::new(&message);
        let first = reader.next_field().unwrap().unwrap();
        assert_eq!(
            first,
            Field {
                number: 1,
                value: FieldValue::Varint(150)
            }
        );
        let second = reader.next_field().unwrap().unwrap();
        assert_eq!(second.string(), Ok("testing"));
        assert_eq!(reader.next_field(), Ok(None));
    }

    #[test]
    fn fixed_fields_decode() {
        // Field 3 fixed64 (key 0x19) and field 4 fixed32 (key 0x25).
        let bytes = [0x19, 1, 0, 0, 0, 0, 0, 0, 0, 0x25, 2, 0, 0, 0];
        let mut reader = FieldReader::new(&bytes);
        assert_eq!(
            reader.next_field(),
            Ok(Some(Field {
                number: 3,
                value: FieldValue::Fixed64(1)
            }))
        );
        assert_eq!(
            reader.next_field(),
            Ok(Some(Field {
                number: 4,
                value: FieldValue::Fixed32(2)
            }))
        );
    }

    #[test]
    fn rejects_malformed_keys_and_lengths() {
        // Wire type 3 opens a deprecated group.
        assert_eq!(
            FieldReader::new(&[0x0b]).next_field(),
            Err(ProtobufError::InvalidWireType(3))
        );
        // Field number 0 is reserved.
        assert_eq!(
            FieldReader::new(&[0x00, 0x01]).next_field(),
            Err(ProtobufError::InvalidFieldNumber)
        );
        // A length of 5 with only 2 bytes left.
        assert_eq!(
            FieldReader::new(&[0x0a, 0x05, 1, 2]).next_field(),
            Err(ProtobufError::Truncated)
        );
        // A fixed64 with 3 of its 8 bytes.
        assert_eq!(
            FieldReader::new(&[0x09, 1, 2, 3]).next_field(),
            Err(ProtobufError::Truncated)
        );
    }

    #[test]
    fn length_prefixed_frames() {
        // A 3-byte body behind a 1-byte prefix.
        let buffer = [0x03, 7, 8, 9, 0xaa];
        assert_eq!(
            split_length_prefixed(&buffer, 16),
            Ok(Some((&[7u8, 8, 9][..], 4)))
        );
        // Only 2 of the 3 body bytes arrived.
        assert_eq!(split_length_prefixed(&buffer[..3], 16), Ok(None));
        // A bound of 2 rejects the header before the body arrives.
        assert_eq!(
            split_length_prefixed(&buffer[..1], 2),
            Err(ProtobufError::FrameTooLarge { len: 3, max: 2 })
        );
    }

    proptest! {
        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            // Walk every field until the reader stops, by error or end.
            let mut reader = FieldReader::new(&bytes);
            while let Ok(Some(_)) = reader.next_field() {}
            let _ = split_length_prefixed(&bytes, 32);
        }

        #[test]
        fn fields_round_trip(number in 1u32..(1 << 29), value: u64, bytes in proptest::collection::vec(any::<u8>(), 0..32)) {
            // One varint field and one bytes field under the same number.
            let mut out = Vec::new();
            encode_varint_field(number, value, &mut out);
            encode_bytes_field(number, &bytes, &mut out);
            let mut reader = FieldReader::new(&out);
            prop_assert_eq!(reader.next_field().unwrap().unwrap().varint(), Ok(value));
            prop_assert_eq!(reader.next_field().unwrap().unwrap().bytes(), Ok(&bytes[..]));
            prop_assert_eq!(reader.next_field(), Ok(None));
        }
    }
}
