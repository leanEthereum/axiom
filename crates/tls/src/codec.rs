//! The TLS presentation language: big-endian integers and length-prefixed vectors.
//!
//! A vector <min..max> carries a length prefix of one, two, or three bytes, by the size of max.
//! See RFC 8446, section 3.

use super::ProtocolError;

/// The width of a vector's length prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Width {
    /// One byte, for vectors up to 255 bytes.
    U8,
    /// Two bytes, for vectors up to 65535 bytes.
    U16,
    /// Three bytes, for vectors up to 2^24 - 1 bytes.
    U24,
}

impl Width {
    /// Bytes of the prefix.
    const fn len(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U24 => 3,
        }
    }
}

/// A cursor over the fields of one message.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a> {
    /// The bytes not yet read.
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over a message body.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// Whether every byte has been read.
    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The bytes not yet read, without consuming them.
    pub(crate) const fn remaining(&self) -> &'a [u8] {
        self.rest
    }

    /// Fails unless every byte has been read.
    pub(crate) const fn finish(&self) -> Result<(), ProtocolError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes {
                count: self.rest.len(),
            })
        }
    }

    /// The next bytes, of a fixed count.
    pub(crate) const fn bytes(&mut self, count: usize) -> Result<&'a [u8], ProtocolError> {
        if self.rest.len() < count {
            return Err(ProtocolError::Truncated {
                needed: count,
                available: self.rest.len(),
            });
        }
        let (bytes, rest) = self.rest.split_at(count);
        self.rest = rest;
        Ok(bytes)
    }

    /// The next bytes, as an array.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let mut out = [0; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    /// The next byte.
    pub(crate) fn u8(&mut self) -> Result<u8, ProtocolError> {
        self.array::<1>().map(|[byte]| byte)
    }

    /// The next big-endian 16-bit integer.
    pub(crate) fn u16(&mut self) -> Result<u16, ProtocolError> {
        self.array().map(u16::from_be_bytes)
    }

    /// The next big-endian integer of a prefix width.
    pub(crate) fn length(&mut self, width: Width) -> Result<usize, ProtocolError> {
        Ok(self
            .bytes(width.len())?
            .iter()
            .fold(0, |value, &byte| (value << 8) | usize::from(byte)))
    }

    /// The next vector, checked against its bounds and item size, as a reader over its body.
    pub(crate) fn vector(
        &mut self,
        width: Width,
        min: usize,
        max: usize,
        item: usize,
    ) -> Result<Self, ProtocolError> {
        let length = self.length(width)?;
        if length < min || length > max || !length.is_multiple_of(item) {
            return Err(ProtocolError::InvalidVectorLength {
                length,
                min,
                max,
                item,
            });
        }
        self.bytes(length).map(Self::new)
    }

    /// The bytes not yet read, consuming them.
    pub(crate) const fn rest(&mut self) -> &'a [u8] {
        let rest = self.rest;
        self.rest = &[];
        rest
    }
}

/// An append-only message buffer.
#[derive(Debug, Default)]
pub(crate) struct Writer {
    /// The bytes written so far.
    out: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    pub(crate) const fn new() -> Self {
        Self { out: Vec::new() }
    }

    /// The written bytes.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    /// Appends one byte.
    pub(crate) fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    /// Appends a big-endian 16-bit integer.
    pub(crate) fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends raw bytes.
    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    /// Appends a vector whose body the closure writes, behind its length prefix.
    ///
    /// # Panics
    ///
    /// Panics when the body outgrows the prefix; every vector this stack writes is far shorter.
    pub(crate) fn vector(&mut self, width: Width, body: impl FnOnce(&mut Self)) {
        // Reserve the prefix, write the body, then fill the prefix in.
        let start = self.out.len();
        self.out.resize(start + width.len(), 0);
        body(self);
        let length = self.out.len() - start - width.len();
        assert!(
            length < 1 << (8 * width.len()),
            "vector body exceeds its length prefix"
        );
        let prefix = &(length as u32).to_be_bytes()[4 - width.len()..];
        self.out[start..start + width.len()].copy_from_slice(prefix);
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn vector_bounds_are_enforced() {
        // A u16 list of two suites: 00 04 13 01 13 03.
        let bytes = [0x00, 0x04, 0x13, 0x01, 0x13, 0x03];
        let mut list = Reader::new(&bytes).vector(Width::U16, 2, 65534, 2).unwrap();
        assert_eq!((list.u16(), list.u16()), (Ok(0x1301), Ok(0x1303)));
        assert_eq!(list.finish(), Ok(()));

        // Mutation: an odd length, 3 bytes for 2-byte items.
        assert_eq!(
            Reader::new(&[0x00, 0x03, 1, 2, 3])
                .vector(Width::U16, 2, 65534, 2)
                .unwrap_err(),
            ProtocolError::InvalidVectorLength {
                length: 3,
                min: 2,
                max: 65534,
                item: 2
            }
        );

        // Mutation: the length claims 4 bytes, 2 follow.
        assert_eq!(
            Reader::new(&[0x04, 1, 2])
                .vector(Width::U8, 0, 255, 1)
                .unwrap_err(),
            ProtocolError::Truncated {
                needed: 4,
                available: 2
            }
        );
    }

    proptest! {
        #[test]
        fn vectors_round_trip(body in proptest::collection::vec(any::<u8>(), 0..300)) {
            // Law: a written u24 vector reads back as its body.
            let mut writer = Writer::new();
            writer.vector(Width::U24, |inner| inner.bytes(&body));
            let bytes = writer.into_bytes();
            let mut reader = Reader::new(&bytes);
            let mut read = reader.vector(Width::U24, 0, 1 << 24, 1).unwrap();
            prop_assert_eq!(read.rest(), &body[..]);
            prop_assert_eq!(reader.finish(), Ok(()));
        }
    }
}
