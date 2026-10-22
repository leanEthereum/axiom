//! Decoding a container one field at a time.

use crate::{BYTES_PER_LENGTH_OFFSET, DecodeError, Ssz, offset::Offset};

/// Hands out a container's fields in declaration order.
///
/// # Overview
///
/// The encoding is a fixed part followed by the bodies of variable fields.
///
/// ```text
/// [fixed a][offset b][fixed c][offset d] [body b][body d]
///                                         ^ first offset = length of fixed part
/// ```
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
    fields: &'static [Option<usize>],
    /// Index of the next field to decode.
    index: usize,
    /// Position of the next field in the fixed part.
    cursor: usize,
    /// Length of the fixed part.
    fixed_part_len: usize,
}

impl<'a> FieldDecoder<'a> {
    /// Decoder over a container encoding, after checking its overall shape.
    pub(crate) fn new(
        bytes: &'a [u8],
        fields: &'static [Option<usize>],
        fixed_part_len: usize,
    ) -> Result<Self, DecodeError> {
        let decoder = Self {
            bytes,
            fields,
            index: 0,
            cursor: 0,
            fixed_part_len,
        };

        // A container without variable fields is exactly its fixed part.
        let Some(first_variable) = fields.iter().position(Option::is_none) else {
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
        let first_offset = Offset::read(bytes, decoder.position_of(first_variable))?;
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
        debug_assert_eq!(
            self.fields.get(self.index).copied().flatten(),
            T::FIXED_SIZE,
            "field {} does not match its declared size",
            self.index
        );

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
    pub(crate) fn finish(self) {
        debug_assert_eq!(self.index, self.fields.len(), "container skipped a field");
        debug_assert_eq!(self.cursor, self.fixed_part_len);
    }

    /// End of the current variable field's body.
    ///
    /// It is the next variable field's offset, or the end of the input when none follows.
    fn end_of_variable_field(&self) -> Result<usize, DecodeError> {
        let next_variable = self.fields[self.index + 1..]
            .iter()
            .position(Option::is_none)
            .map(|step| self.index + 1 + step);

        let end = match next_variable {
            Some(field) => Offset::read(self.bytes, self.position_of(field))?,
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

    /// Position of a field within the fixed part.
    fn position_of(&self, field: usize) -> usize {
        self.fields[..field]
            .iter()
            .map(|size| size.unwrap_or(BYTES_PER_LENGTH_OFFSET))
            .sum()
    }
}
