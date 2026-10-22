//! A cursor that reads canonical RLP items off a byte slice.

use crate::{
    RlpError,
    header::{Header, Kind},
};

/// Reads RLP items in order from a byte slice, borrowing every payload.
///
/// # Overview
///
/// Each read consumes one item and checks its shape.
/// A list read returns a child decoder over the list's payload.
/// Reading ends with a check that nothing is left over.
///
/// Every read is strict.
/// A byte string has at most one accepted reading, so equal values have equal encodings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoder<'a> {
    /// Bytes not read yet.
    rest: &'a [u8],
}

impl<'a> Decoder<'a> {
    /// A decoder over a whole input.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    /// Whether every item has been read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The kind of the next item, without reading it.
    ///
    /// # Errors
    ///
    /// Fails when the next header is malformed or no item is left.
    pub fn peek_kind(&self) -> Result<Kind, RlpError> {
        // Decoding the header validates it, so a later read cannot disagree.
        Header::decode(self.rest).map(|(header, _)| header.kind)
    }

    /// Reads the next item whole, header included.
    ///
    /// # Errors
    ///
    /// Fails when the header is malformed or the item runs past the input.
    pub fn raw(&mut self) -> Result<&'a [u8], RlpError> {
        // The item spans its header and its payload.
        let (header, offset) = Header::decode(self.rest)?;
        let (item, rest) = self.rest.split_at(offset + header.payload_len);
        self.rest = rest;
        Ok(item)
    }

    /// Reads the next item as a byte string.
    ///
    /// # Errors
    ///
    /// Fails when the item is a list or is malformed.
    pub fn bytes(&mut self) -> Result<&'a [u8], RlpError> {
        // Split the header from its payload.
        let (header, offset) = Header::decode(self.rest)?;
        if header.kind != Kind::String {
            return Err(RlpError::ExpectedString);
        }
        let (item, rest) = self.rest.split_at(offset + header.payload_len);
        self.rest = rest;
        Ok(&item[offset..])
    }

    /// Reads the next item as a byte string of exactly N bytes.
    ///
    /// # Errors
    ///
    /// Fails when the item is a list, is malformed, or has another length.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], RlpError> {
        // Fixed-size targets such as keys and signatures accept one length only.
        let payload = self.bytes()?;
        payload.try_into().map_err(|_| RlpError::WrongLength {
            expected: N,
            found: payload.len(),
        })
    }

    /// Reads the next item as an unsigned 64-bit integer.
    ///
    /// # Errors
    ///
    /// Fails when the payload has a leading zero byte or more than 8 bytes.
    pub fn uint(&mut self) -> Result<u64, RlpError> {
        // Canonical integers are minimal: no leading zero, at most the target's width.
        let payload = self.bytes()?;
        if payload.first() == Some(&0) {
            return Err(RlpError::LeadingZeroInInteger);
        }
        if payload.len() > size_of::<u64>() {
            return Err(RlpError::IntegerOverflow {
                max: size_of::<u64>(),
                found: payload.len(),
            });
        }
        // Accumulate big-endian; eight bytes cannot overflow 64 bits.
        Ok(payload
            .iter()
            .fold(0, |value, &byte| (value << 8) | u64::from(byte)))
    }

    /// Reads the next item as an unsigned 16-bit integer, such as a port.
    ///
    /// # Errors
    ///
    /// Fails like a 64-bit read, and when the value exceeds 16 bits.
    pub fn u16(&mut self) -> Result<u16, RlpError> {
        // Read wide, then narrow; a minimal encoding wider than 2 bytes overflows.
        let value = self.uint()?;
        u16::try_from(value).map_err(|_| RlpError::IntegerOverflow {
            max: size_of::<u16>(),
            found: 8 - value.leading_zeros() as usize / 8,
        })
    }

    /// Reads the next item as a list and returns a decoder over its items.
    ///
    /// # Errors
    ///
    /// Fails when the item is a string or is malformed.
    pub fn list(&mut self) -> Result<Self, RlpError> {
        // The child decoder sees exactly the list's payload.
        let (header, offset) = Header::decode(self.rest)?;
        if header.kind != Kind::List {
            return Err(RlpError::ExpectedList);
        }
        let (item, rest) = self.rest.split_at(offset + header.payload_len);
        self.rest = rest;
        Ok(Self::new(&item[offset..]))
    }

    /// Checks that every item has been read.
    ///
    /// # Errors
    ///
    /// Fails when bytes remain.
    pub const fn finish(self) -> Result<(), RlpError> {
        // Trailing bytes would give one value two encodings.
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(RlpError::TrailingBytes {
                remaining: self.rest.len(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::Item;

    #[test]
    fn integers_refuse_padding_and_overflow() {
        // 0x80 is zero, 0x7f is 127, 0x82 0x03 0xe8 is 1000.
        assert_eq!(Decoder::new(&[0x80]).uint(), Ok(0));
        assert_eq!(Decoder::new(&[0x7f]).uint(), Ok(127));
        assert_eq!(Decoder::new(&[0x82, 0x03, 0xe8]).uint(), Ok(1000));
        // 0x00 is the byte zero, not the integer zero.
        assert_eq!(
            Decoder::new(&[0x00]).uint(),
            Err(RlpError::LeadingZeroInInteger)
        );
        // 0x82 0x00 0x01 pads 1 with a zero byte.
        assert_eq!(
            Decoder::new(&[0x82, 0x00, 0x01]).uint(),
            Err(RlpError::LeadingZeroInInteger)
        );
        // Nine bytes exceed 64 bits.
        let mut nine = vec![0x89];
        nine.extend_from_slice(&[1; 9]);
        assert_eq!(
            Decoder::new(&nine).uint(),
            Err(RlpError::IntegerOverflow { max: 8, found: 9 })
        );
        // 0x83 0x01 0x00 0x00 is 65536, one past the largest port.
        assert_eq!(
            Decoder::new(&[0x83, 0x01, 0x00, 0x00]).u16(),
            Err(RlpError::IntegerOverflow { max: 2, found: 3 })
        );
        assert_eq!(Decoder::new(&[0x82, 0x76, 0x5f]).u16(), Ok(30303));
    }

    #[test]
    fn shapes_are_checked() {
        // A list where a string is expected, and the reverse.
        assert_eq!(Decoder::new(&[0xc0]).bytes(), Err(RlpError::ExpectedString));
        assert_eq!(Decoder::new(&[0x80]).list(), Err(RlpError::ExpectedList));
        // A 3-byte string for a 4-byte array.
        assert_eq!(
            Decoder::new(&[0x83, 1, 2, 3]).array::<4>(),
            Err(RlpError::WrongLength {
                expected: 4,
                found: 3
            })
        );
        // Trailing bytes after the only item.
        let mut decoder = Decoder::new(&[0x01, 0x02]);
        assert_eq!(decoder.uint(), Ok(1));
        assert_eq!(
            decoder.finish(),
            Err(RlpError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn raw_and_peek_leave_items_whole() {
        // [ "dog" ] then 0x05.
        let input = [0xc4, 0x83, b'd', b'o', b'g', 0x05];
        let mut decoder = Decoder::new(&input);
        assert_eq!(decoder.peek_kind(), Ok(Kind::List));
        assert_eq!(decoder.raw(), Ok(&input[..5]));
        assert_eq!(decoder.peek_kind(), Ok(Kind::String));
        assert_eq!(decoder.raw(), Ok(&input[5..]));
        assert!(decoder.is_empty());
    }

    proptest! {
        #[test]
        fn decoding_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            // Every typed read returns a value or an error.
            let _ = Item::decode(&bytes);
            let mut decoder = Decoder::new(&bytes);
            let _ = decoder.uint();
            let _ = Decoder::new(&bytes).u16();
            let _ = Decoder::new(&bytes).array::<32>();
            let _ = Decoder::new(&bytes).list().map(|mut list| list.raw());
        }
    }
}
