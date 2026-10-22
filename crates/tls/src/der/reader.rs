//! Reading DER values one at a time, refusing every non-canonical encoding.

use super::{DerError, Tag};

/// Most long-form length bytes accepted: four bytes reach 4 GiB, far beyond any certificate.
const MAX_LENGTH_BYTES: usize = 4;

/// A cursor over consecutive DER values.
#[derive(Clone, Copy, Debug)]
pub struct DerReader<'a> {
    /// The bytes not yet read.
    rest: &'a [u8],
}

impl<'a> DerReader<'a> {
    /// A reader over a run of values.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// Whether every value has been read.
    pub const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The tag of the next value, without reading it.
    pub fn peek_tag(&self) -> Option<Tag> {
        self.rest.first().map(|&tag| Tag(tag))
    }

    /// Reads the next value whatever its tag, returning the tag and the content.
    ///
    /// # Errors
    ///
    /// Fails on a truncated or non-canonical header, or the high tag number form.
    pub fn any(&mut self) -> Result<(Tag, &'a [u8]), DerError> {
        let tag = self.peek_tag().ok_or(DerError::Truncated {
            needed: 1,
            available: 0,
        })?;
        self.element(tag).map(|content| (tag, content))
    }

    /// Reads the next value only when it carries the tag.
    ///
    /// # Errors
    ///
    /// Fails when a value with the tag is present but malformed.
    pub fn optional(&mut self, tag: Tag) -> Result<Option<&'a [u8]>, DerError> {
        if self.peek_tag() == Some(tag) {
            self.element(tag).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Reads an INTEGER of any sign and returns its two's complement content.
    ///
    /// The content must be minimal, as DER requires.
    ///
    /// # Errors
    ///
    /// Fails on an empty or non-minimal integer.
    pub fn integer(&mut self) -> Result<&'a [u8], DerError> {
        let content = self.element(Tag::INTEGER)?;
        match content {
            [] => Err(DerError::EmptyInteger),
            // A leading 0x00 may only clear a sign bit, and a leading 0xff may only set one.
            [0x00, next, ..] if next & 0x80 == 0 => Err(DerError::NonMinimalInteger),
            [0xff, next, ..] if next & 0x80 != 0 => Err(DerError::NonMinimalInteger),
            _ => Ok(content),
        }
    }

    /// Fails unless every value has been read.
    pub const fn finish(&self) -> Result<(), DerError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DerError::TrailingBytes {
                count: self.rest.len(),
            })
        }
    }

    /// Reads the next value, which must carry the tag, and returns its content.
    pub fn element(&mut self, tag: Tag) -> Result<&'a [u8], DerError> {
        self.element_with_encoding(tag).map(|(content, _)| content)
    }

    /// Reads the next value, which must carry the tag.
    ///
    /// # Returns
    ///
    /// The content, then the whole encoding: tag, length, and content.
    /// Signatures cover the whole encoding, so certificates need both.
    pub fn element_with_encoding(&mut self, tag: Tag) -> Result<(&'a [u8], &'a [u8]), DerError> {
        let start = self.rest;
        let (&found, rest) = start.split_first().ok_or(DerError::Truncated {
            needed: 1,
            available: 0,
        })?;
        // The high tag number form sets all five low bits.
        if found & 0x1f == 0x1f {
            return Err(DerError::HighTagNumber(found));
        }
        if found != tag.0 {
            return Err(DerError::UnexpectedTag {
                expected: tag.0,
                found,
            });
        }
        let mut cursor = rest;
        let length = Self::length(&mut cursor)?;
        if cursor.len() < length {
            return Err(DerError::Truncated {
                needed: length,
                available: cursor.len(),
            });
        }
        let (content, rest) = cursor.split_at(length);
        let header = start.len() - cursor.len();
        self.rest = rest;
        Ok((content, &start[..header + length]))
    }

    /// Reads a SEQUENCE and returns a reader over its values.
    pub fn sequence(&mut self) -> Result<Self, DerError> {
        self.element(Tag::SEQUENCE).map(Self::new)
    }

    /// Reads a non-negative INTEGER and returns its magnitude without a sign byte.
    ///
    /// Zero reads as one zero byte.
    pub fn unsigned_integer(&mut self) -> Result<&'a [u8], DerError> {
        let content = self.element(Tag::INTEGER)?;
        let (&first, tail) = content.split_first().ok_or(DerError::EmptyInteger)?;
        if first & 0x80 != 0 {
            return Err(DerError::NegativeInteger);
        }
        match tail.first() {
            // A leading zero may only clear the sign bit of the byte after it.
            Some(&next) if first == 0 && next & 0x80 == 0 => Err(DerError::NonMinimalInteger),
            Some(_) if first == 0 => Ok(tail),
            _ => Ok(content),
        }
    }

    /// Reads a non-negative INTEGER that fits in 64 bits.
    pub fn small_integer(&mut self) -> Result<u64, DerError> {
        let magnitude = self.unsigned_integer()?;
        if magnitude.len() > 8 {
            return Err(DerError::IntegerTooLong {
                length: magnitude.len(),
                max: 8,
            });
        }
        Ok(magnitude
            .iter()
            .fold(0, |value, &byte| (value << 8) | u64::from(byte)))
    }

    /// Reads a BOOLEAN.
    pub fn boolean(&mut self) -> Result<bool, DerError> {
        // X.690, section 11.1: true is all ones in DER.
        match self.element(Tag::BOOLEAN)? {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(DerError::InvalidBoolean),
        }
    }

    /// Reads an OCTET STRING.
    pub fn octet_string(&mut self) -> Result<&'a [u8], DerError> {
        self.element(Tag::OCTET_STRING)
    }

    /// Reads an OBJECT IDENTIFIER and returns its encoded arcs, for comparison with constants.
    pub fn object_identifier(&mut self) -> Result<&'a [u8], DerError> {
        self.element(Tag::OBJECT_IDENTIFIER)
    }

    /// Reads a BIT STRING of whole bytes and returns those bytes.
    pub fn bit_string(&mut self) -> Result<&'a [u8], DerError> {
        // The first content byte counts the unused bits of the last byte.
        match self.element(Tag::BIT_STRING)?.split_first() {
            Some((0, bytes)) => Ok(bytes),
            _ => Err(DerError::PartialBitString),
        }
    }

    /// Reads a BIT STRING of named bits, as the bits from the first onward, most significant first.
    ///
    /// The unused trailing bits must be zero, as DER requires.
    ///
    /// # Returns
    ///
    /// The content bytes, then the count of unused bits in the last one.
    ///
    /// # Errors
    ///
    /// Fails on an empty content, more than seven unused bits, or a set unused bit.
    pub fn named_bits(&mut self) -> Result<(&'a [u8], u8), DerError> {
        let (&unused, bytes) = self
            .element(Tag::BIT_STRING)?
            .split_first()
            .ok_or(DerError::PartialBitString)?;
        let last = bytes.last().copied().unwrap_or(0);
        let mask = 1_u8
            .checked_shl(u32::from(unused))
            .map_or(0xff, |bit| bit - 1);
        if unused > 7 || (bytes.is_empty() && unused != 0) || last & mask != 0 {
            return Err(DerError::PartialBitString);
        }
        Ok((bytes, unused))
    }

    /// Decodes a definite length in its shortest form, advancing past it.
    fn length(cursor: &mut &'a [u8]) -> Result<usize, DerError> {
        let (&first, rest) = cursor.split_first().ok_or(DerError::Truncated {
            needed: 1,
            available: 0,
        })?;
        *cursor = rest;
        if first < 0x80 {
            return Ok(usize::from(first));
        }
        if first == 0x80 {
            return Err(DerError::IndefiniteLength);
        }

        // Long form: the low seven bits count the big-endian length bytes that follow.
        let count = usize::from(first & 0x7f);
        if count > MAX_LENGTH_BYTES {
            return Err(DerError::LengthTooLong {
                count,
                max: MAX_LENGTH_BYTES,
            });
        }
        if cursor.len() < count {
            return Err(DerError::Truncated {
                needed: count,
                available: cursor.len(),
            });
        }
        let (bytes, rest) = cursor.split_at(count);
        *cursor = rest;
        let length = bytes
            .iter()
            .fold(0_usize, |value, &byte| (value << 8) | usize::from(byte));

        // X.690, section 10.1: the long form only for 128 and up, with no leading zero byte.
        if length < 0x80 || bytes[0] == 0 {
            return Err(DerError::NonMinimalLength { length });
        }
        Ok(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads one element of the tag and requires nothing after it.
    fn read_one(bytes: &[u8], tag: Tag) -> Result<&[u8], DerError> {
        let mut reader = DerReader::new(bytes);
        let content = reader.element(tag)?;
        reader.finish()?;
        Ok(content)
    }

    #[test]
    fn short_and_long_lengths() {
        // 127 bytes fit the short form; 128 need 0x81 0x80.
        let mut short = vec![0x04, 0x7f];
        short.extend([7; 127]);
        assert_eq!(read_one(&short, Tag::OCTET_STRING), Ok(&[7; 127][..]));
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([7; 128]);
        assert_eq!(read_one(&long, Tag::OCTET_STRING), Ok(&[7; 128][..]));

        // 256 bytes need two length bytes: 0x82 0x01 0x00.
        let mut two = vec![0x04, 0x82, 0x01, 0x00];
        two.extend([7; 256]);
        assert_eq!(read_one(&two, Tag::OCTET_STRING), Ok(&[7; 256][..]));
    }

    #[test]
    fn non_canonical_lengths_are_refused() {
        // Mutation: 5 written in the long form, 0x81 0x05.
        assert_eq!(
            read_one(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5], Tag::OCTET_STRING),
            Err(DerError::NonMinimalLength { length: 5 })
        );
        // Mutation: 128 written with a leading zero, 0x82 0x00 0x80.
        let mut padded = vec![0x04, 0x82, 0x00, 0x80];
        padded.extend([0; 128]);
        assert_eq!(
            read_one(&padded, Tag::OCTET_STRING),
            Err(DerError::NonMinimalLength { length: 128 })
        );
        // Mutation: the indefinite form.
        assert_eq!(
            read_one(&[0x30, 0x80, 0x00, 0x00], Tag::SEQUENCE),
            Err(DerError::IndefiniteLength)
        );
        // Mutation: five length bytes.
        assert_eq!(
            read_one(&[0x04, 0x85, 1, 0, 0, 0, 0], Tag::OCTET_STRING),
            Err(DerError::LengthTooLong { count: 5, max: 4 })
        );
        // Mutation: the length claims 3 bytes, 2 follow.
        assert_eq!(
            read_one(&[0x04, 0x03, 1, 2], Tag::OCTET_STRING),
            Err(DerError::Truncated {
                needed: 3,
                available: 2
            })
        );
    }

    #[test]
    fn tags_are_checked() {
        // A SET where a SEQUENCE belongs, and a high tag number.
        assert_eq!(
            read_one(&[0x31, 0x00], Tag::SEQUENCE),
            Err(DerError::UnexpectedTag {
                expected: 0x30,
                found: 0x31
            })
        );
        assert_eq!(
            read_one(&[0x1f, 0x22, 0x00], Tag::SEQUENCE),
            Err(DerError::HighTagNumber(0x1f))
        );
        // Mutation: a byte after the value.
        assert_eq!(
            read_one(&[0x05, 0x00, 0x00], Tag(0x05)),
            Err(DerError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn integers_are_minimal_and_non_negative() {
        fn integer(bytes: &[u8]) -> Result<&[u8], DerError> {
            DerReader::new(bytes).unsigned_integer()
        }

        // 0, 127, and 128 with its sign byte.
        assert_eq!(integer(&[0x02, 0x01, 0x00]), Ok(&[0x00][..]));
        assert_eq!(integer(&[0x02, 0x01, 0x7f]), Ok(&[0x7f][..]));
        assert_eq!(integer(&[0x02, 0x02, 0x00, 0x80]), Ok(&[0x80][..]));

        // Mutation: 1 with a redundant zero, -128, and no content.
        assert_eq!(
            integer(&[0x02, 0x02, 0x00, 0x01]),
            Err(DerError::NonMinimalInteger)
        );
        assert_eq!(integer(&[0x02, 0x01, 0x80]), Err(DerError::NegativeInteger));
        assert_eq!(integer(&[0x02, 0x00]), Err(DerError::EmptyInteger));

        // 2^64 does not fit a small integer.
        assert_eq!(
            DerReader::new(&[0x02, 0x09, 1, 0, 0, 0, 0, 0, 0, 0, 0]).small_integer(),
            Err(DerError::IntegerTooLong { length: 9, max: 8 })
        );
        assert_eq!(
            DerReader::new(&[0x02, 0x02, 0x01, 0x00]).small_integer(),
            Ok(256)
        );
    }

    #[test]
    fn booleans_and_bit_strings() {
        // True is 0xff, false is 0x00, anything else is refused.
        assert_eq!(DerReader::new(&[0x01, 0x01, 0xff]).boolean(), Ok(true));
        assert_eq!(DerReader::new(&[0x01, 0x01, 0x00]).boolean(), Ok(false));
        assert_eq!(
            DerReader::new(&[0x01, 0x01, 0x01]).boolean(),
            Err(DerError::InvalidBoolean)
        );

        // A bit string of whole bytes, then one with three unused bits, then an empty one.
        assert_eq!(
            DerReader::new(&[0x03, 0x02, 0x00, 0xaa]).bit_string(),
            Ok(&[0xaa][..])
        );
        assert_eq!(
            DerReader::new(&[0x03, 0x02, 0x03, 0xa8]).bit_string(),
            Err(DerError::PartialBitString)
        );
        assert_eq!(
            DerReader::new(&[0x03, 0x00]).bit_string(),
            Err(DerError::PartialBitString)
        );
    }

    #[test]
    fn whole_encodings_are_returned() {
        // The encoding spans tag, length, and content.
        let bytes = [0x30, 0x03, 0x02, 0x01, 0x05, 0xee];
        let mut reader = DerReader::new(&bytes);
        let (content, encoding) = reader.element_with_encoding(Tag::SEQUENCE).unwrap();
        assert_eq!(content, &[0x02, 0x01, 0x05]);
        assert_eq!(encoding, &bytes[..5]);
        assert_eq!(reader.peek_tag(), Some(Tag(0xee)));
    }
}
