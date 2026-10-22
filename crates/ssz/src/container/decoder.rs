//! Decoding a container one field at a time.

use super::Layout;
use crate::{BYTES_PER_LENGTH_OFFSET, DecodeError, Ssz, offset::Offset};

/// Hands out a container's fields in declaration order.
///
/// # Overview
///
/// The encoding is a fixed part followed by the bodies of variable fields.
///
/// ```text
/// [fixed a][offset b][fixed c][offset d] [body b][body d]
/// ```
///
/// The first offset equals the length of the fixed part, where the first body starts.
///
/// A variable body runs from its offset to the next variable field's offset.
/// The last body runs to the end of the input.
///
/// # Invariants
///
/// Every check the spec demands happens before a field is returned.
/// The first offset ends the fixed part, offsets never decrease, and none passes the end.
#[derive(Debug)]
pub struct FieldDecoder<'a> {
    /// The whole container encoding.
    bytes: &'a [u8],
    /// Fixed sizes as declared.
    layout: Layout,
    /// Index of the next field to decode.
    index: usize,
    /// Position of the next field in the fixed part.
    cursor: usize,
}

impl<'a> FieldDecoder<'a> {
    /// Decoder over a container encoding, after checking its overall shape.
    pub(super) fn new(bytes: &'a [u8], layout: Layout) -> Result<Self, DecodeError> {
        let fixed_part_len = layout.fixed_part_len();
        let decoder = Self {
            bytes,
            layout,
            index: 0,
            cursor: 0,
        };

        // A container without variable fields is exactly its fixed part.
        let Some(first_variable) = layout.next_variable(0) else {
            if bytes.len() != fixed_part_len {
                return Err(DecodeError::InvalidLength {
                    expected: fixed_part_len,
                    actual: bytes.len(),
                });
            }
            return Ok(decoder);
        };

        if bytes.len() < fixed_part_len {
            return Err(DecodeError::TooShort {
                minimum: fixed_part_len,
                actual: bytes.len(),
            });
        }

        // Invariant: the first offset points right past the fixed part, leaving no gap.
        let first_offset = Offset::read(bytes, layout.position_of(first_variable))?;
        if first_offset != fixed_part_len {
            return Err(DecodeError::FirstOffsetMismatch {
                expected: fixed_part_len,
                actual: first_offset,
            });
        }

        Ok(decoder)
    }

    /// Decodes the next field.
    ///
    /// # Errors
    ///
    /// Fails when the field's bytes do not decode, or its offsets are malformed.
    pub fn field<T: Ssz>(&mut self) -> Result<T, DecodeError> {
        self.layout.check::<T>(self.index);

        let value = match T::FIXED_SIZE {
            Some(size) => T::decode(&self.bytes[self.cursor..self.cursor + size])?,
            None => {
                let start = Offset::read(self.bytes, self.cursor)?;
                let end = self.end_of_variable_field()?;
                if end < start {
                    return Err(DecodeError::OffsetsNotIncreasing {
                        previous: start,
                        next: end,
                    });
                }
                T::decode(&self.bytes[start..end])?
            }
        };

        self.cursor += T::FIXED_SIZE.unwrap_or(BYTES_PER_LENGTH_OFFSET);
        self.index += 1;
        Ok(value)
    }

    /// Confirms every declared field was decoded, in debug builds.
    pub(super) fn finish(self) {
        debug_assert_eq!(self.index, self.layout.len(), "container skipped a field");
        debug_assert_eq!(self.cursor, self.layout.fixed_part_len());
    }

    /// End of the current variable field's body.
    ///
    /// It is the next variable field's offset, or the end of the input when none follows.
    fn end_of_variable_field(&self) -> Result<usize, DecodeError> {
        let end = match self.layout.next_variable(self.index + 1) {
            Some(field) => Offset::read(self.bytes, self.layout.position_of(field))?,
            None => self.bytes.len(),
        };

        if end > self.bytes.len() {
            return Err(DecodeError::OffsetOutOfBounds {
                offset: end,
                length: self.bytes.len(),
            });
        }
        Ok(end)
    }
}
