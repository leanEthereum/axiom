//! From SSZ bytes to JSON, along a schema.

use axiom_ssz::{BYTES_PER_LENGTH_OFFSET, DecodeError, Field, Schema};

use super::uint::LittleEndian;
use crate::{Data, Json, Object};

/// The SSZ encoding of one value, read as JSON.
#[derive(Clone, Copy, Debug)]
pub(crate) struct JsonEncoder<'a>(&'a [u8]);

impl<'a> JsonEncoder<'a> {
    /// Reads the given encoding.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// The JSON form of the encoded value.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not an encoding of the schema's type.
    pub(crate) fn value(self, schema: &Schema) -> Result<Json, DecodeError> {
        let bytes = self.0;
        match *schema {
            Schema::Boolean => Ok(Json::Bool(bytes.first().is_some_and(|byte| *byte != 0))),
            Schema::Uint { .. } => Ok(LittleEndian::from_bytes(bytes).to_decimal().into()),
            // Byte strings and bitfields alike go out as the hex of their encoding.
            Schema::ByteVector { .. }
            | Schema::ByteList { .. }
            | Schema::ProgressiveByteList
            | Schema::BitVector { .. }
            | Schema::BitList { .. }
            | Schema::ProgressiveBitList => Ok(bytes.to_data().into()),
            Schema::Vector { element, .. }
            | Schema::List { element, .. }
            | Schema::ProgressiveList { element } => self.sequence(element),
            Schema::Container { fields } => self.container(fields),
            Schema::Union { options } => {
                let (&selector, data) = bytes.split_first().ok_or(DecodeError::TooShort {
                    minimum: 1,
                    actual: 0,
                })?;
                let option = options
                    .iter()
                    .find(|option| option.selector() == selector)
                    .ok_or(DecodeError::UnknownSelector { selector })?;
                Ok(Json::from([
                    ("selector", u64::from(selector).to_string().into()),
                    ("data", Self(data).value(option.schema())?),
                ]))
            }
        }
    }

    /// The elements of a vector or list.
    fn sequence(self, element: &Schema) -> Result<Json, DecodeError> {
        let bytes = self.0;
        let items = match element.fixed_size() {
            // Fixed-size elements sit back to back.
            Some(size) => bytes
                .chunks(size)
                .map(|chunk| Self(chunk).value(element))
                .collect::<Result<_, _>>()?,
            // Variable-size elements: an offset table, whose first entry says how long it is.
            None if bytes.is_empty() => Vec::new(),
            None => {
                let count = Self::offset(bytes, 0)? / BYTES_PER_LENGTH_OFFSET;
                let offsets = (0..count)
                    .map(|index| Self::offset(bytes, index * BYTES_PER_LENGTH_OFFSET))
                    .collect::<Result<Vec<_>, _>>()?;
                Self::bodies(bytes, &offsets)?
                    .into_iter()
                    .map(|body| Self(body).value(element))
                    .collect::<Result<_, _>>()?
            }
        };
        Ok(Json::Array(items))
    }

    /// The fields of a container, by name.
    fn container(self, fields: &[Field]) -> Result<Json, DecodeError> {
        let bytes = self.0;
        // Phase 1: walk the fixed part, slicing fixed fields and collecting offsets.
        let mut position = 0;
        let mut fixed = Vec::with_capacity(fields.len());
        let mut offsets = Vec::new();
        for field in fields {
            let width = field.schema().fixed_part_size();
            match field.size() {
                Some(_) => {
                    let end = position + width;
                    let slice = bytes.get(position..end).ok_or(DecodeError::TooShort {
                        minimum: end,
                        actual: bytes.len(),
                    })?;
                    fixed.push(Some(slice));
                }
                None => {
                    offsets.push(Self::offset(bytes, position)?);
                    fixed.push(None);
                }
            }
            position += width;
        }

        // Phase 2: variable fields take the bodies between consecutive offsets.
        let mut bodies = Self::bodies(bytes, &offsets)?.into_iter();
        let mut object = Object::new();
        for (field, slice) in fields.iter().zip(fixed) {
            let slice = match slice {
                Some(slice) => slice,
                None => bodies.next().ok_or(DecodeError::TooShort {
                    minimum: position,
                    actual: bytes.len(),
                })?,
            };
            object.insert(field.name(), Self(slice).value(field.schema())?);
        }
        Ok(Json::Object(object))
    }

    /// The bodies the offsets point at, each running to the next offset or the end.
    fn bodies<'b>(bytes: &'b [u8], offsets: &[usize]) -> Result<Vec<&'b [u8]>, DecodeError> {
        let mut bodies = Vec::with_capacity(offsets.len());
        for (index, &start) in offsets.iter().enumerate() {
            let end = offsets.get(index + 1).copied().unwrap_or(bytes.len());
            if start > end {
                return Err(DecodeError::OffsetsNotIncreasing {
                    previous: start,
                    next: end,
                });
            }
            bodies.push(
                bytes
                    .get(start..end)
                    .ok_or(DecodeError::OffsetOutOfBounds {
                        offset: end,
                        length: bytes.len(),
                    })?,
            );
        }
        Ok(bodies)
    }

    /// The little-endian offset at a position.
    fn offset(bytes: &[u8], at: usize) -> Result<usize, DecodeError> {
        let end = at + BYTES_PER_LENGTH_OFFSET;
        let raw = bytes.get(at..end).ok_or(DecodeError::TooShort {
            minimum: end,
            actual: bytes.len(),
        })?;
        let mut word = [0; BYTES_PER_LENGTH_OFFSET];
        word.copy_from_slice(raw);
        Ok(u32::from_le_bytes(word) as usize)
    }
}
