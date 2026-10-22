//! Walking the fields of one encoded message.

use std::str;

use super::ProtobufError;
use crate::varint::{Varint, VarintError};

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
                let (bytes, rest) = self
                    .rest
                    .split_at_checked(len)
                    .ok_or(ProtobufError::Truncated)?;
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
        Varint::Protobuf
            .read(&mut self.rest)
            .map_err(|error| match error {
                VarintError::Truncated => ProtobufError::Truncated,
                other => ProtobufError::Varint(other),
            })
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

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
        // A key varint cut short after its continuation bit.
        assert_eq!(
            FieldReader::new(&[0x88]).next_field(),
            Err(ProtobufError::Truncated)
        );
    }

    proptest! {
        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            // Walk every field until the reader stops, by error or end.
            let mut reader = FieldReader::new(&bytes);
            while let Ok(Some(_)) = reader.next_field() {}
        }
    }
}
